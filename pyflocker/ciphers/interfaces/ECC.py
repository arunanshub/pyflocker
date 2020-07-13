from .. import load_cipher as _load_cpr


def _load_ecc_cpr(backend):
    """Load the cipher module from the backend."""
    return _load_cpr('ECC', backend)


def generate(curve, *, backend=None):
    """
    Generate a private key with given curve `curve`.

    `backend` must be an attribute of `Backends`.
    """
    return _load_ecc_cpr(backend).ECCPrivateKey(curve)


def load_public_key(data, *, backend=None):
    """Loads the public key and returns a Key interface.

    `backend` must be an attribute of `Backends`.
    """
    return _load_ecc_cpr(backend).ECCPublicKey.load(data)


def load_private_key(data, passphrase=None, *, backend=None):
    """Loads the private key and returns a Key interface.
    
    If the private key was not encrypted duting the serialization,
    `passphrase` must be `None`, otherwise it must be a `bytes` object.

    `backend` must be an attribute of `Backends`.
    """
    return _load_ecc_cpr(backend).ECCPrivateKey.load(data, passphrase)
