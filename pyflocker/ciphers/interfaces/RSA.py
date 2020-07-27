"""Interface to RSA cipher and signature algorithm"""
from .. import load_cipher as _load_cpr


def _load_rsa_cpr(backend):
    """Load the cipher module from the backend."""
    return _load_cpr('RSA', backend)


def generate(bits, e=65537, *, backend=None):
    """
    Generate a private key with given key modulus `bits` and
    public exponent `e` (default 65537).
    Recommended size of `bits` > 1024.

    Args:
        bits: The bit length of the RSA key.
        e: The public exponent value. Default is 65537.

    Kwargs:
        backend: The backend to use. It must be a value from `Backends`.

    Returns:
        A RSAPrivateKey object.
    """
    return _load_rsa_cpr(backend).RSAPrivateKey(bits, e)


def load_public_key(data, *, backend=None):
    """Loads the public key and returns a Key interface.

    Args:
        data: The public key (a bytes-like object) to deserialize.

    Kwargs:
        backend: The backend to use. It must be a value from `Backends`.

    Returns:
        An RSAPublicKey interface.
    """
    return _load_rsa_cpr(backend).RSAPublicKey.load(data)


def load_private_key(data, passphrase=None, *, backend=None):
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    `passphrase` must be `None`, otherwise it must be a `bytes` object.

    Args:
        data:
            The private key (a bytes-like object) to deserialize.
        passphrase:
            The password (in bytes) that was used to encrypt the
            private key.`None` if the private key was not encrypted.

    Kwargs:
        backend:
            The backend to use. It must be a value from `Backends`.

    Returns:
        An RSAPrivateKey interface.
    """
    return _load_rsa_cpr(backend).RSAPrivateKey.load(data, passphrase)
