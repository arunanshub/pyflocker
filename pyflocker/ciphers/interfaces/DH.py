"""Interface to DH key exchange"""
from .. import load_cipher as _load_cpr
from .. import Backends


def _load_dhe(backend):
    """Load the cipher module from the backend."""
    return _load_cpr('DH', backend)


def generate(key_size, g=2, *, backend=Backends.CRYPTOGRAPHY):
    """
    Generate DHE parameter with prime number's bit size `bits` and
    generator `e` (default 65537). Recommended size of `bits` > 1024.

    Args:
        key_size: The bit length of the prime modulus to generate
        g: The `int` to use as a generator value. Default is 2.

    Kwargs:
        backend: The backend to use. It must be a value from `Backends`.

    Returns:
        A DH key exchange paramenter object.
    """
    return _load_dhe(backend).DHParameters(key_size, g)


def load_from_parameters(p, g=2, q=None, *, backend=Backends.CRYPTOGRAPHY):
    """Create a DHParameter object from the given parameters.

    Args:
        p: The prime modulus `p` as `int`.
        g: The generator
        q: `p` subgroup order value.

    Kwargs:
        backend: The backend to use. It must be a value from `Backends`.
    """
    return _load_dhe(backend).DHParameters.load_from_parameters(p, g, q)


def load_public_key(data, *, backend=Backends.CRYPTOGRAPHY):
    """Loads the public key and returns a Key interface.

    Args:
        data: The public key (a bytes-like object) to deserialize.

    Kwargs:
        backend: The backend to use. It must be a value from `Backends`.

    Returns:
        An DHPublicKey interface.
    """
    return _load_dhe(backend).DHPublicKey.load(data)


def load_private_key(data, passphrase=None, *, backend=Backends.CRYPTOGRAPHY):
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    `passphrase` must be `None`, otherwise it must be a `bytes` object.

    Args:
        data:
            The private key (a bytes-like object) to deserialize.
        password:
            The password (in bytes) that was used to encrypt the
            private key.`None` if the password was not encrypted

    Kwargs:
        backend:
            The backend to use. It must be a value from `Backends`.

    Returns:
        An DHPrivateKey interface.
    """
    return _load_dhe(backend).DHPrivateKey.load(data, passphrase)
