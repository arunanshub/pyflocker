"""Interface to ChaCha20-Poly1305 cipher"""
from ..backends import load_algorithm as _load_algo


def new(locking, key, nonce, *, file=None, backend=None):
    """Instantiate a new ChaCha20-Poly1305 cipher wrapper object.

    Args:
        locking (bool):
            True is encryption and False is decryption.
        key (bytes, bytearray, memoryview):
            The key for the cipher.
        nonce (bytes, bytearray, memoryview):
            The Nonce for the cipher.
            It must not be repeated with the same key.

    Keyword Arguments:
        file (filelike):
            The source file to read from.
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        :any:`Cipher`:
            ChaCha20Poly1305 cipher wrapper from the appropriate backend module.

    Raises:
        NotImplementedError: if backend does not support that mode.
        ModuleNotFoundError: if the backend is not found.

    Note:
        Any other error that is raised is from the backend itself.
    """
    cpr = _load_algo("ChaCha20", backend)
    if file:
        _cpr = cpr.ChaCha20Poly1305File
        return _cpr(locking, key, nonce, file=file)
    else:
        _cpr = cpr.ChaCha20Poly1305
        return _cpr(locking, key, nonce)
