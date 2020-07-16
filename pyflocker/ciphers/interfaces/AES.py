"""AES Cipher

The AES cipher module eases your creation of AES-XXX mode
ciphers, where `XXX` is the mode. Its support depends ultimately
upon the underlying backend.

The modes and the involved intricacies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""

from .. import load_cipher as _load_cpr, Modes as _m
from .. import aead, special

# shortcut for calling like Crypto.Cipher.AES.new(key, AES.MODE_XXX, ...)
globals().update({val.name: val for val in list(_m)})


def _aes_cipher_from_mode(mode, bknd, hasfile):
    if mode not in bknd.supported.keys():
        raise NotImplementedError("backend does not support this mode.")

    if mode in aead:
        if mode in special:
            if hasfile:
                raise TypeError('this mode does not support R/W to file')
            return bknd.AEADOneShot
        if hasfile:
            return bknd.AEADFile
        return bknd.AEAD
    else:
        if hasfile:
            return bknd.NonAEADFile
        return bknd.NonAEAD


def new(locking, key, mode, iv_or_nonce, *, file=None, backend=None, **kwargs):
    """Make a new AES cipher wrapper.

    locking: True is encryption and False is decryption.
    key: The key for the cipher.
    mode: The mode to use. A backend may not support it.

    file: The source file to read from.
    backend: The backend to use.
             It must be a value from `ciphers.backends.Backends`

    *args, **kwargs:
        Additional arguments and values that must be passed
        during the creation of cipher. Depends upon backend.

    Return: AES cipher wrapper from the appropriate backend module.

    Raises: `NotImplementedError` if backend does not support that mode.
            `ModuleNotFoundError` if the backend is not found.
             Any other error that is raised is from the backend itself.
    """
    cpr = _load_cpr("AES", backend)
    _cpr = _aes_cipher_from_mode(mode, cpr, file is not None)

    if file:
        if mode not in aead:
            kwargs.update(dict(hashed=True))  # always use HMAC
        return _cpr(locking, key, mode, iv_or_nonce, file=file, **kwargs)
    return _cpr(locking, key, mode, iv_or_nonce, **kwargs)
