"""AES Cipher

The AES cipher module eases your creation of AES-XXX mode
ciphers, where `XXX` is the mode. Its support depends ultimately
upon the underlying backend.

The modes and the involved intricacies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""


from .. import load_cipher as _load_cpr, Modes as _m
from .. import aead, special


def _aes_cipher_from_mode(mode, bknd):
    if mode not in bknd.supported.keys():
        raise NotImplementedError(
            "backend does not support this mode.")

    if mode in aead:
        if mode in special:
            return bknd.AEADOneShot
        return bknd.AEAD
    else:
        return bknd.NonAEAD


def new(file, locking, key, mode, *args,
        backend=None, **kwargs):
    """Make a new AES cipher wrapper.

    file: The source file to read from.
    locking: True is encryption and False is decryption.
    key: The key for the cipher.
    mode: The mode to use. A backend may not support it.
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
    return _aes_cipher_from_mode(mode, cpr)(
        file, locking, key, mode, *args, **kwargs)

