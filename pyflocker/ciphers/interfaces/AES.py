"""Interface to AES cipher"""

import typing

from ..backends import Backends as _Backends
from ..backends import load_algorithm as _load_algo
from ..modes import Modes as _m
from ..modes import aead, special

# shortcut for calling like Crypto.Cipher.AES.new(key, AES.MODE_XXX, ...)
globals().update({val.name: val for val in list(_m)})


def supported_modes(backend):
    """Lists all modes supported by the cipher. It is limited to backend's
    implementation and capability, and hence, varies from backend to backend.

    Args:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            An attribute from :any:`Backends` enum.

    Returns:
        list: list of :any:`Modes` object supported by backend.
    """
    return list(_load_algo("AES", backend).supported)


def new(
    encrypting: bool,
    key: typing.ByteString,
    mode: _m,
    iv_or_nonce: typing.ByteString,
    *,
    use_hmac: bool = False,
    digestmod: str = "sha256",
    file: typing.Optional[typing.BinaryIO] = None,
    backend: _Backends = None,
):
    """Instantiate a new AES cipher object.

    Args:
        encrypting (bool):
            True is encryption and False is decryption.
        key (bytes, bytearray, memoryview):
            The key for the cipher.
        mode (:class:`pyflocker.ciphers.modes.Modes`):
            The mode to use for AES cipher. All backends may not support
            that particular mode.
        iv_or_nonce (bytes, bytearray, memoryview):
            The Initialization Vector or Nonce for the cipher. It must not be
            repeated with the same key.

    Keyword Arguments:
        file (filelike):
            The source file to read from. If `file` is specified
            and the `mode` is not an AEAD mode, HMAC is always used.
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.
        use_hmac (bool):
            Should the cipher use HMAC as authentication or not,
            if it does not support AEAD. (Default: False)
        digestmod (str):
            The algorithm to use for HMAC. Defaults to `sha256`.
            Specifying this value without setting `hashed` to True
            has no effect.

    Important:
        The following arguments must not be passed if the mode is an AEAD mode:

        - hashed
        - digestmod

    Returns:
        :any:`BaseCipher`:
            AES cipher wrapper from the appropriate backend module.

    Raises:
        ValueError: if the `mode` is an AEAD mode and still the extra kwargs
            are provided.
        NotImplementedError: if backend does not support that mode.
        UnsupportedAlgorithm: if the backend does not support AES.

    Note:
        Any other error that is raised is from the backend itself.
    """
    return _load_algo("AES", backend).new(
        encrypting,
        key,
        mode,
        iv_or_nonce,
        use_hmac=use_hmac,
        digestmod=digestmod,
        file=file,
    )
