"""AES Cipher

todo
"""


from . import load_backend as _load_bknd


def _aes_cipher_from_mode(mode, bknd):
    if mode not in bknd.supported.keys():
        raise NotImplementedError(
            "backend does not support this mode.")

    if mode in aead:
        if mode in special:
            return bknd.AESAEADOneShot
        return bknd.AESAEAD
    else:
        return bknd.AESNonAEAD


def new(file, locking, key, mode, *args,
        backend=None, **kwargs):
    """Make a new AES cipher wrapper."""
    bknd = _load_bknd(backend)
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
