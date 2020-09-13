"""Interface to AES cipher"""

from ..backends import load_algorithm as _load_algo, Modes as _m
from .. import aead, special

# shortcut for calling like Crypto.Cipher.AES.new(key, AES.MODE_XXX, ...)
globals().update({val.name: val for val in list(_m)})


def _aes_cipher_from_mode(mode, bknd, hasfile):
    if mode not in supported_modes(bknd):
        raise NotImplementedError("backend does not support this mode.")

    cpr = _load_algo('AES', bknd)
    if mode in aead:
        if mode in special:
            if hasfile:
                raise TypeError('this mode does not support R/W to file')
            return cpr.AEADOneShot
        if hasfile:
            return cpr.AEADFile
        return cpr.AEAD
    else:
        if hasfile:
            return cpr.NonAEADFile
        return cpr.NonAEAD


def supported_modes(backend):
    """Lists all modes supported by the cipher. It is
    limited to backend's implementation and capability,
    and hence, varies from backend to backend.

    Args:
        backend: An attribute from Backends enum.

    Returns:
        list of Modes object supported by backend.
    """
    return list(_load_algo('AES', backend).supported)


def new(locking, key, mode, iv_or_nonce, *, file=None, backend=None, **kwargs):
    """Instantiate a new AES cipher wrapper object.

    Args:
        locking:
            True is encryption and False is decryption.
        key:
            The key for the cipher.
        mode:
            The mode to use for AES cipher. All backends may not support
            that particular mode.
        iv_or_nonce:
            The Initialization Vector or Nonce for the cipher. It must not be
            repeated with the same key.

    Kwargs:
        file:
            The source file to read from. If `file` is specified
            and the `mode` is not an AEAD mode, HMAC is always used.
        backend:
            The backend to use. It must be a value from `Backends`.

        The following arguments must not be passed if the `mode` is an
        AEAD mode.
        hashed:
            Should the cipher use HMAC as authentication or not,
            if it does not support AEAD. (Default: False)
        digestmod:
            The algorithm to use for HMAC. Defaults to `sha256`.
            Specifying this value without setting `hashed` to True
            has no effect.

    Returns:
        AES cipher wrapper from the appropriate backend module.

    Raises:
        `ValueError` if the `mode` is an AEAD mode and still the
        extra kwargs are provided.
        `NotImplementedError` if backend does not support that mode.
        `UnsupportedAlgorithm` if the backend does not support AES.
        Any other error that is raised is from the backend itself.
    """
    _cpr = _aes_cipher_from_mode(mode, backend, file is not None)

    if file:
        if mode not in aead:
            kwargs.update(dict(hashed=True))  # always use HMAC
        return _cpr(locking, key, mode, iv_or_nonce, file=file, **kwargs)
    return _cpr(locking, key, mode, iv_or_nonce, **kwargs)
