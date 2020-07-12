from .. import load_cipher as _load_cpr
from .. import Backends


def _load_dhe(backend):
    """Load the cipher module from the backend."""
    return _load_cpr('DH', backend)


def generate(key_size, g=2, *, backend=Backends.CRYPTOGRAPHY):
    """
    Generate DHE parameter with prime number's bit size `bits` and
    generator `e` (default 65537).
    Recommended size of `bits` > 1024.

    `backend` must be an attribute of `Backends`.
    """
    return _load_dhe(backend).DHParameters(key_size, g)


def load_from_parameters(p, g=2, q=None):
    return _load_dhe(backend).DHParameters.load_from_parameters(p, g, q)


def load_public_key(data, *, backend=Backends.CRYPTOGRAPHY):
    """Loads the public key and returns a Key interface.

    `backend` must be an attribute of `Backends`.
    """
    return _load_dhe(backend).DHPublicKey.load(data)


def load_private_key(data, passphrase=None, *, backend=Backends.CRYPTOGRAPHY):
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    `passphrase` must be `None`, otherwise it must be a `bytes` object.

    `backend` must be an attribute of `Backends`.
    """
    return _load_dhe(backend).DHPrivateKey.load(data, passphrase)
