"""Interface to ChaCha20(-Poly1305) cipher"""
import typing

from .. import base as _base
from ..backends import Backends as _Backends
from ..backends import load_algorithm as _load_algo


def new(
    encrypting: bool,
    key: typing.ByteString,
    nonce: typing.ByteString,
    *,
    use_poly1305: bool = True,
    file: typing.Optional[typing.BinaryIO] = None,
    backend: typing.Optional[_Backends] = None,
) -> typing.Union[_base.BaseNonAEADCipher, _base.BaseAEADCipher]:
    """Instantiate a new ChaCha20-Poly1305 cipher wrapper object.

    Args:
        encrypting (bool):
            True is encryption and False is decryption.
        key (bytes, bytearray, memoryview):
            The key for the cipher.
        nonce (bytes, bytearray, memoryview):
            The Nonce for the cipher.
            It must not be repeated with the same key.

    Keyword Arguments:
        use_poly1305 (bool):
            Whether Poly1305 MAC will be used (``True``) or not (``False``).
            Default is ``True``.
        file (filelike):
            The source file to read from.
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        BaseSymmetricCipher:
            ChaCha20(Poly1305) cipher from the appropriate backend module.

    Note:
        Any other error that is raised is from the backend itself.
    """
    return _load_algo("ChaCha20", backend).new(
        encrypting,
        key,
        nonce,
        file=file,
        use_poly1305=use_poly1305,
    )
