"""Interface to AES cipher"""

import typing

from .. import base as _base
from ..backends import Backends as _Backends
from ..backends import load_algorithm as _load_algo
from ..modes import Modes as _m

# shortcut for calling like Crypto.Cipher.AES.new(key, AES.MODE_XXX, ...)
globals().update({val.name: val for val in list(_m)})


def supported_modes(backend: _Backends) -> typing.Set[_m]:
    """Lists all modes supported by the cipher. It is limited to backend's
    implementation and capability, and hence, varies from backend to backend.

    Args:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            An attribute from :any:`Backends` enum.

    Returns:
        set: set of :any:`Modes` object supported by backend.
    """
    return _load_algo("AES", backend).supported_modes()


def new(
    encrypting: bool,
    key: bytes,
    mode: _m,
    iv_or_nonce: bytes,
    *,
    use_hmac: bool = False,
    tag_length: typing.Optional[int] = 16,
    digestmod: typing.Union[str, _base.BaseHash] = "sha256",
    file: typing.Optional[typing.BinaryIO] = None,
    backend: typing.Optional[_Backends] = None,
) -> typing.Union[_base.BaseNonAEADCipher, _base.BaseAEADCipher]:
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
        use_hmac (bool):
            Should the cipher use HMAC as authentication or not, if it does
            not support AEAD. (Default: False)
        tag_length (int, None):
            Length of HMAC tag. By default, a **16 byte tag** is generated. If
            ``tag_length`` is ``None``, a **non-truncated** tag is generated.
            Length of non-truncated tag depends on the digest size of the
            underlying hash algorithm used by HMAC.
        digestmod (str, BaseHash):
            The algorithm to use for HMAC. Defaults to ``sha256``.
            Specifying this value without setting ``use_hmac`` to True
            has no effect.
        file (filelike):
            The source file to read from. If ``file`` is specified
            and the ``mode`` is not an AEAD mode, HMAC is always used.
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Important:
        The following arguments are ignored if the mode is an AEAD mode:

        - ``use_hmac``
        - ``tag_length``
        - ``digestmod``

    Returns:
        BaseSymmetricCipher:
            AES cipher wrapper from the appropriate backend module.

    Raises:
        NotImplementedError:
            if backend does not support the given mode or the mode does not
            support encryption/decryption of files.
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
        tag_length=tag_length,
        digestmod=digestmod,
        file=file,
    )
