from .. import load_cipher as _load_cpr


def _load_rsa_cpr(backend):
    """Load the cipher module from the backend."""
    return _load_cpr('RSA', backend)


def generate(bits, e=65537, *, backend=None):
    """
    Generate a private key with given key modulus `bits` and
    public exponent `e` (default 65537).
    Recommended size of `bits` > 1024.

    `backend` must be an attribute of `Backends`.
    """
    return _load_rsa_cpr(backend).RSAPrivateKey(bits, e)


def load_public_key(data, *, backend=None):
    """Loads the public key and returns a Key interface.

    `backend` must be an attribute of `Backends`.
    """
    return _load_rsa_cpr(backend).RSAPublicKey.load(data)


def load_private_key(data, passphrase=None, *, backend=None):
    """Loads the private key and returns a Key interface.
    
    If the private key was not encrypted duting the serialization,
    `passphrase` must be `None`, otherwise it must be a `bytes` object.

    `backend` must be an attribute of `Backends`.
    """
    return _load_rsa_cpr(backend).RSAPrivateKey.load(data, passphrase)
