"""Interface to ChaCha20-Poly1305 cipher"""
from .. import load_cipher as _load_cpr


def new(locking, key, nonce, *, file=None, backend=None):
    """Instantiate a new ChaCha20-Poly1305 cipher wrapper object.

    Args:
        locking:
            True is encryption and False is decryption.
        key:
            The key for the cipher.
        nonce:
            The Nonce for the cipher.
            It must not be repeated with the same key.

    Kwargs:
        file:
            The source file to read from.
        backend:
            The backend to use. It must be a value from `Backends`.

    Returns:
        ChaCha20Poly1305 cipher wrapper from the appropriate backend module.

    Raises:
        `NotImplementedError` if backend does not support that mode.
        `ModuleNotFoundError` if the backend is not found.
        Any other error that is raised is from the backend itself.
    """
    cpr = _load_cpr("ChaCha20", backend)
    if file:
        _cpr = cpr.ChaCha20Poly1305File
        return _cpr(locking, key, nonce, file=file)
    else:
        _cpr = cpr.ChaCha20Poly1305
        return _cpr(locking, key, nonce)
