"""Implementation of AES cipher."""

from types import MappingProxyType

from Cryptodome.Cipher import AES

from .symmetric import (
    AEADCipherTemplate,
    NonAEADCipherTemplate,
)

from .misc import derive_hkdf_key
from ..symmetric import HMACWrapper, FileCipherWrapper
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
    """Create a new backend specific AES cipher.

    Args:
        encrypting (bool):
            True is encryption and False is decryption.
        key (bytes, bytearray, memoryview):
            The key for the cipher.
        mode (:any:`Modes`):
            The mode to use for AES cipher. All backends may not support
            that particular mode.
        iv_or_nonce (bytes, bytearray, memoryview):
            The Initialization Vector or Nonce for the cipher. It must not be
            repeated with the same key.

    Keyword Arguments:
        file (filelike):
            The source file to read from. If `file` is specified
            and the `mode` is not an AEAD mode, HMAC is always used.
        use_hmac (bool):
            Should the cipher use HMAC as authentication or not,
            if it does not support AEAD. (Default: False)
        digestmod (str):
            The algorithm to use for HMAC. Defaults to `sha256`.
            Specifying this value without setting `hashed` to True
            has no effect.

    Important:
        The following arguments must not be passed if the mode is an AEAD mode:
          - use_hmac
          - digestmod

    Returns:
        :any:`BaseCipher`: AES cipher.

    Raises:
        ValueError: if the `mode` is an AEAD mode and still the extra kwargs
            are provided.

    Note:
        Any other error that is raised is from the backend itself.
    """
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


def supported_modes():
    """Lists all modes supported by AES cipher of this backend.

    Args:
        None
    Returns:
        list: list of :any:`Modes` object supported by backend.
    """
    return list(supported)


def _wrap_hmac(encrypting, key, mode, iv_or_nonce, digestmod):
    ckey, hkey = derive_hkdf_key(key, len(key), digestmod, iv_or_nonce)
    crp = HMACWrapper(
        NonAEAD(encrypting, ckey, mode, iv_or_nonce),
        hkey,
        iv_or_nonce,
        digestmod,
    )
    return crp


def _get_aes_cipher(key, mode, iv_or_nonce):
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
    """AES-AEAD cipher class.

    Adapts the AES cipher from Cryptodome backend.
    """

    def __init__(self, encrypting, key, mode, nonce):
        self._cipher = _get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting
        # creating a context is relatively expensive here
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )


class NonAEAD(NonAEADCipherTemplate):
    """AES-NonAEAD cipher class.

    Adapts the AES cipher from Cryptodome backend.
    """

    def __init__(self, encrypting, key, mode, nonce):
        self._cipher = _get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting

        # creating a context is relatively expensive here
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )


class AEADOneShot(AEAD):
    """AES-AEAD-OneShot cipher class.

    Adapts the backend specific AES cipher modes which support one shot
    operation.
    """

    def __init__(self, encrypting, key, mode, nonce):
        self._cipher = _get_aes_cipher(key, mode, nonce)
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
            # decryption error is ignored, and raised from finalize method
            pass

        self.finalize(tag)
        return data
