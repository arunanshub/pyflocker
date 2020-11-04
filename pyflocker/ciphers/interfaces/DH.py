"""Interface to DH key exchange"""
from ..backends import load_algorithm as _load_algo
from .. import Backends


def _load_dhe(backend):
    """Load the cipher module from the backend."""
    return _load_algo("DH", backend)


def generate(key_size, g=2, *, backend=Backends.CRYPTOGRAPHY):
    """
    Generate DHE parameter with prime number's bit size `bits` and
    generator `g` (default 2). Recommended size of `bits` > 1024.

    Args:
        key_size (int): The bit length of the prime modulus.
        g (int): The value to use as a generator value. Default is 2.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        :any:`DHParameters`: A DH key exchange paramenter object.
    """
    return _load_dhe(backend).DHParameters(key_size, g)


def load_from_parameters(p, g=2, q=None, *, backend=Backends.CRYPTOGRAPHY):
    """Create a DHParameter object from the given parameters.

    Args:
        p (int): The prime modulus `p` as `int`.
        g (int): The generator.
        q (int): `p` subgroup order value.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        :any:`DHParameters`: A DH key exchange paramenter object.
    """
    return _load_dhe(backend).DHParameters.load_from_parameters(p, g, q)


def load_parameters(data, *, backend=Backends.CRYPTOGRAPHY):
    """Deserialize the DH parameters and load a parameter object.

    Args:
        data (bytes): Serialized DH Parameter.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        :any:`DHParameters`: A `DHParameters` object.
    """
    return _load_dhe(backend).DHParameters.load(data)


def load_public_key(data, *, backend=Backends.CRYPTOGRAPHY):
    """Loads the public key and returns a Key interface.

    Args:
        data (bytes, bytearray):
            The public key (a bytes-like object) to deserialize.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        :any:`BasePublicKey`: An DHPublicKey interface.
    """
    return _load_dhe(backend).DHPublicKey.load(data)


def load_private_key(data, passphrase=None, *, backend=Backends.CRYPTOGRAPHY):
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    `passphrase` must be `None`, otherwise it must be a `bytes` object.

    Args:
        data (bytes, bytearray):
            The private key (a bytes-like object) to deserialize.
        password (bytes, bytearray):
            The password (in bytes) that was used to encrypt the
            private key.`None` if the key was not encrypted.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        :any:`BasePrivateKey`: An DHPrivateKey interface.
    """
    return _load_dhe(backend).DHPrivateKey.load(data, passphrase)
