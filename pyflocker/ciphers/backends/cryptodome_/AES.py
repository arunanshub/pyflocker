"""Implementation of AES cipher."""

import typing
from types import MappingProxyType

from Cryptodome.Cipher import AES

from ... import base, exc, modes
from ...modes import Modes as _m
from ..symmetric import FileCipherWrapper, HMACWrapper
from .misc import derive_hkdf_key
from .symmetric import AEADCipherTemplate, NonAEADCipherTemplate

SUPPORTED = MappingProxyType(
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

    return AES.new(key, SUPPORTED[mode], *args, **kwargs)


class AEAD(AEADCipherTemplate):
    """AES-AEAD cipher class.

    Adapts the AES cipher from Cryptodome backend.
    """

    def __init__(self, encrypting, key, mode, nonce):
        self._cipher = _get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting
        self._mode = mode
        # creating a context is relatively expensive here
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )

    @property
    def mode(self) -> _m:
        """The AES mode."""
        return self._mode


class NonAEAD(NonAEADCipherTemplate):
    """AES-NonAEAD cipher class.

    Adapts the AES cipher from Cryptodome backend.
    """

    def __init__(self, encrypting, key, mode, nonce):
        self._cipher = _get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting
        self._mode = mode

        # creating a context is relatively expensive here
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )

    @property
    def mode(self) -> _m:
        """The AES mode."""
        return self._mode


class AEADOneShot(AEAD):
    """AES-AEAD-OneShot cipher class.

    Adapts the backend specific AES cipher modes which support one shot
    operation.
    """

    def __init__(self, encrypting, key, mode, nonce):
        self._cipher = _get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting
        self._mode = mode

        # creating a context is relatively expensive here
        self._update_func = self._get_update_func(encrypting, self._cipher)

    @property
    def mode(self) -> _m:
        """The AES mode."""
        return self._mode

    @staticmethod
    def _get_update_func(encrypting, cipher):
        if encrypting:
            func = cipher.encrypt_and_digest
            return lambda data, tag=None, **k: func(data, **k)[0]

        func = cipher.decrypt_and_verify
        return lambda data, tag, **k: func(data, tag, **k)

    def update(self, data, tag=None):
        return self.update_into(data, None, tag)

    def update_into(self, data, out, tag=None):
        if self._update_func is None:
            raise exc.AlreadyFinalized

        if not self._encrypting:
            if tag is None:
                raise ValueError("tag is required for decryption.")

        try:
            try:
                data = self._update_func(data, tag, output=out)
            except TypeError as e:
                # incorrect nos. of arguments.
                if out is not None:
                    raise TypeError(
                        f"{self._mode} does not support writing into mutable "
                        "buffers"
                    ) from e
                data = self._update_func(data, tag)
        except ValueError:
            # decryption error is ignored, and raised from finalize method
            pass

        self.finalize(tag)
        return data


def new(
    encrypting: bool,
    key: typing.ByteString,
    mode: _m,
    iv_or_nonce: typing.ByteString,
    *,
    file: typing.Optional[typing.BinaryIO] = None,
    use_hmac: bool = False,
    digestmod: [str, base.BaseHash] = "sha256",
) -> typing.Union[AEAD, NonAEAD, AEADOneShot, FileCipherWrapper, HMACWrapper]:
    """Create a new backend specific AES cipher.

    Args:
        encrypting (bool):
            True is encryption and False is decryption.
        key (bytes, bytearray, memoryview):
            The key for the cipher.
        mode (:any:`Modes`):
            The mode to use for AES cipher.
        iv_or_nonce (bytes, bytearray, memoryview):
            The Initialization Vector or Nonce for the cipher. It must not be
            repeated with the same key.

    Keyword Arguments:
        file (filelike):
            The source file to read from. If ``file`` is specified
            and the ``mode`` is not an AEAD mode, HMAC is always used.
        use_hmac (bool):
            Should the cipher use HMAC as authentication or not,
            if it does not support AEAD. (Default: False)
        digestmod (str, BaseHash):
            The algorithm to use for HMAC. Defaults to ``sha256``.
            Specifying this value without setting ``use_hmac`` to True
            has no effect.

    Important:
        The following arguments are ignored if the mode is an AEAD mode:

        - ``use_hmac``
        - ``digestmod``

    Returns:
        Union[BaseAEADCipher, BaseNonAEADCipher]: AES cipher.

    Raises:
        NotImplementedError:
            if the ``mode`` does not support encryption/decryption of files or
            the mode is not supported by the backend.

    Note:
        Any other error that is raised is from the backend itself.
    """
    crp: typing.Any

    if file is not None:
        use_hmac = True

    if mode not in supported_modes():
        raise NotImplementedError(f"{mode} not supported.")

    if mode in modes.special:
        if file is not None:
            raise NotImplementedError(
                f"{mode} does not support encryption/decryption of files."
            )
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


def supported_modes() -> typing.Set[_m]:
    """Lists all modes supported by AES cipher of this backend.

    Returns:
        set: set of :any:`Modes` object supported by backend.
    """
    return set(SUPPORTED)


def _wrap_hmac(encrypting, key, mode, iv_or_nonce, digestmod):
    ckey, hkey = derive_hkdf_key(key, len(key), digestmod, iv_or_nonce)
    crp = HMACWrapper(
        NonAEAD(encrypting, ckey, mode, iv_or_nonce),
        hkey,
        iv_or_nonce,
        digestmod,
    )
    return crp
