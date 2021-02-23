"""Interface to DH key exchange"""
import typing

from .. import base
from ..backends import Backends as _Backends
from ..backends import load_algorithm as _load_algo


def _load_dhe(backend):
    return _load_algo("DH", backend)


def generate(
    key_size: int,
    g: int = 2,
    *,
    backend: _Backends = _Backends.CRYPTOGRAPHY,
):
    """
    Generate DHE parameter with prime number's bit size ``bits`` and
    generator ``g`` (default 2). Recommended size of ``bits`` > 1024.

    Args:
        key_size (int): The bit length of the prime modulus.
        g (int): The value to use as a generator value. Default is 2.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        DHParameters: A DH key exchange paramenter object.
    """
    return _load_dhe(backend).generate(key_size, g)


def load_from_parameters(
    p: int,
    g: int = 2,
    q: typing.Optional[int] = None,
    *,
    backend: _Backends = _Backends.CRYPTOGRAPHY,
):
    """Create a DH Parameter object from the given parameters.

    Args:
        p (int): The prime modulus ``p``.
        g (int): The generator.
        q (int): ``p`` subgroup order value.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        DHParameters: A DH key exchange paramenter object.
    """
    return _load_dhe(backend).load_from_parameters(p, g, q)


def load_parameters(
    data: typing.ByteString,
    *,
    backend=_Backends.CRYPTOGRAPHY,
):
    """Deserialize the DH parameters and load a parameter object.

    Args:
        data (bytes): Serialized DH Parameter.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        DHParameters: A DHKE parameter object.
    """
    return _load_dhe(backend).load_parameters(data)


def load_public_key(
    data: typing.ByteString,
    *,
    backend: _Backends = _Backends.CRYPTOGRAPHY,
) -> base.BasePublicKey:
    """Loads the public key and returns a Key interface.

    Args:
        data (bytes, bytearray):
            The public key (a bytes-like object) to deserialize.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        BasePublicKey: An public key object.
    """
    return _load_dhe(backend).load_public_key(data)


def load_private_key(
    data: typing.ByteString,
    passphrase: typing.Optional[typing.ByteString] = None,
    *,
    backend: _Backends = _Backends.CRYPTOGRAPHY,
) -> base.BasePrivateKey:
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    ``passphrase`` must be ``None``, otherwise it must be a ``bytes`` object.

    Args:
        data (bytes, bytearray):
            The private key (a bytes-like object) to deserialize.
        passphrase (bytes, bytearray):
            The passphrase (in bytes) that was used to encrypt the
            private key. ``None`` if the key was not encrypted.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        BasePrivateKey: A private key object.
    """
    return _load_dhe(backend).load_private_key(data, passphrase)
