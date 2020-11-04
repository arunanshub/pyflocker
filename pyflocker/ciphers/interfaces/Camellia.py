"""Interface to Camellia cipher"""

from ..backends import load_algorithm as _load_algo
from .. import Backends


def _cml_cipher_from_mode(mode, bknd, hasfile):
    if mode not in supported_modes(bknd):
        raise NotImplementedError("backend does not support this mode.")
    cpr = _load_algo("Camellia", bknd)
    if not hasfile:
        return cpr.Camellia
    return cpr.CamelliaFile


def supported_modes(backend):
    """Lists all modes supported by the cipher. It is limited to backend's
    implementation and capability and hence, varies from backend to backend.

    Args:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            An attribute from :any:`Backends` enum.

    Returns:
        list: list of :any:`Modes` object supported by backend.
    """
    return list(_load_algo("Camellia", backend).supported)


def new(
    locking,
    key,
    mode,
    iv_or_nonce,
    *,
    file=None,
    backend=Backends.CRYPTOGRAPHY,
    **kwargs
):
    """Instantiate a new Camellia cipher wrapper object.

    Args:
        locking (bool):
            True is encryption and False is decryption.
        key (bytes, bytearray, memoryview):
            The key for the cipher.
        mode (:class:`pyflocker.ciphers.modes.Modes`):
            The mode to use for Camellia cipher. All backends may not support
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
        hashed (bool):
            Should the cipher use HMAC as authentication or not.
            (Default: `False`)
        digestmod (str):
            The algorithm to use for `HMAC`. Defaults to `sha256`.
            Specifying this value without setting `hashed` to True
            has no effect.

    Returns:
        :any:`Cipher`:
            Camellia cipher wrapper from the appropriate backend module.

    Raises:
        NotImplementedError: if backend does not support that mode.
        UnsupportedAlgorithm: if the backend does not support Camellia.

    Note:
        Any other error that is raised is from the backend itself.
    """
    _cpr = _cml_cipher_from_mode(mode, backend, file is not None)
    if file:
        kwargs.update(dict(hashed=True))  # Always use HMAC
        return _cpr(locking, key, mode, iv_or_nonce, file=file, **kwargs)
    return _cpr(locking, key, mode, iv_or_nonce, **kwargs)
