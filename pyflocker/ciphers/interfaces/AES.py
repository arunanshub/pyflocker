"""AES Cipher

The AES cipher module eases your creation of AES-XXX mode
ciphers, where `XXX` is the mode. Its support depends ultimately
upon the underlying backend.

The modes and the involved intricacies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All modes that are globally supported are defined at the module level.

The modes that support AEAD implicitly, can be found in `aead` set
in the module.

Please note that some modes are globally not supported even if the
backend implements them, due to their insecure form or too much
complexity involved in wrapping.

Here are the *unsupported* ones:
    - ECB
    - XTS
    - CBC

Some modes require special treatment as encryption/decryption must happen
in one round. Hence, they do NOT support gradual input of data.
These special modes can be found in `special` set defined in the module.
"""


from .. import load_cipher as _load_cpr


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
    bknd = _load_cpr("AES", backend)
    return _aes_cipher_from_mode(mode, bknd)(
        file, locking, key, mode, *args, **kwargs)


# All AES modes listed here. A backend may not
# support all modes.

MODE_GCM = "MODE_GCM"

MODE_CTR = "MODE_CTR"

# MODE_CBC = "MODE_CBC"

MODE_CFB = "MODE_CFB"

MODE_OFB = "MODE_OFB"

# MODE_OPENPGP = "MODE_OPENPGP"

MODE_CCM = "MODE_CCM"

MODE_EAX = "MODE_EAX"

MODE_SIV = "MODE_SIV"

MODE_OCB = "MODE_OCB"


# authenticated modes
aead = {
    MODE_GCM,
    MODE_CCM,
    MODE_EAX,
    MODE_OCB,
    MODE_SIV,
}


# the special modes
special = {
    MODE_SIV,
    MODE_CCM,
    MODE_OCB,
    # MODE_OPENPGP,
}
