from types import MappingProxyType

from Cryptodome.Cipher import AES

from .symmetric import (
    AEADCipherTemplate,
    NonAEADCipherTemplate,
    FileCipherWrapper,
)

from .misc import derive_hkdf_key
from ..symmetric import HMACWrapper
from ... import base, exc
from ... import modes
from ...modes import Modes as _m


supported = MappingProxyType(
    {
        # classic modes
        _m.MODE_CTR: AES.MODE_CTR,
        _m.MODE_CFB: AES.MODE_CFB,
        _m.MODE_CFB8: AES.MODE_CFB,  # compat with pyca/cryptography
        _m.MODE_OFB: AES.MODE_OFB,
        # AEAD modes
        _m.MODE_GCM: AES.MODE_GCM,
        _m.MODE_EAX: AES.MODE_EAX,
        _m.MODE_SIV: AES.MODE_SIV,
        _m.MODE_CCM: AES.MODE_CCM,
        _m.MODE_OCB: AES.MODE_OCB,
    }
)

del MappingProxyType


def new(
    encrypting,
    key,
    mode,
    iv_or_nonce,
    *,
    file=None,
    use_hmac=False,
    digestmod="sha256",
):
    if mode in modes.special:
        crp = AEADOneShot(encrypting, key, mode, iv_or_nonce)
    elif mode in modes.aead:
        crp = AEAD(encrypting, key, mode, iv_or_nonce)
    else:
        if use_hmac:
            crp = _wrap_hmac(encrypting, key, mode, iv_or_nonce, digestmod)
        else:
            crp = NonAEAD(encrypting, key, mode, iv_or_nonce)

    if file:
        crp = FileCipherWrapper(crp, file)

    return crp


def _wrap_hmac(encrypting, key, mode, iv_or_nonce, digestmod):
    ckey, hkey = derive_hkdf_key(key, len(key), digestmod, iv_or_nonce)
    crp = HMACWrapper(
        NonAEAD(encrypting, ckey, mode, iv_or_nonce),
        hkey,
        iv_or_nonce,
        digestmod,
    )
    return crp


def get_aes_cipher(key, mode, iv_or_nonce):
    args = (iv_or_nonce,)
    kwargs = dict()

    if mode == _m.MODE_CFB:
        # compat with pyca/cryptography's CFB(...) mode
        kwargs = dict(segment_size=128)
    elif mode == _m.MODE_CTR:
        kwargs = dict(
            # initial value of Cryptodome is nonce for pyca/cryptography
            initial_value=int.from_bytes(iv_or_nonce, "big"),
            nonce=b"",
        )
        args = ()

    return AES.new(key, supported[mode], *args, **kwargs)


class AEAD(AEADCipherTemplate):
    def __init__(self, encrypting, key, mode, nonce):
        self._cipher = get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting
        # creating a context is relatively expensive here
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )


class NonAEAD(NonAEADCipherTemplate):
    def __init__(self, encrypting, key, mode, nonce):
        self._cipher = get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting

        # creating a context is relatively expensive here
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )


class AEADOneShot(AEAD):
    def __init__(self, encrypting, key, mode, nonce):
        self._cipher = get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting
        self.__mode = mode

        # creating a context is relatively expensive here
        if encrypting:
            self._update_func = (
                lambda data, *args: self._cipher.encrypt_and_digest(  # noqa
                    data, *args
                )[0]
            )
        else:
            self._update_func = (
                lambda data, *args: self._cipher.decrypt_and_verify(  # noqa
                    data, tag, *args
                )
            )

    def update(self, data):
        return self.update_into(data, None, None)

    def update_into(self, data, out, tag=None):
        if self._update_func is None:
            raise exc.AlreadyFinalized
        if not self._encrypting:
            if tag is None:
                raise ValueError("tag is required for decryption.")

        try:
            try:
                data = self._update_func(data, out)
            except TypeError as e:
                # MODE_OCB does not support writing into buffer.
                if out is not None:
                    raise TypeError(
                        f"{self.__mode} does not support writing into mutable "
                        "buffers"
                    ) from e
                data = self._update_func(data)
        except ValueError:
            pass

        self.finalize(tag)
        return data
