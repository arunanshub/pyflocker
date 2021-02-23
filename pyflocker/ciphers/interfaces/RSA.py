"""Interface to RSA cipher and signature algorithm"""
import typing

from .. import base
from ..backends import Backends as _Backends
from ..backends import load_algorithm as _load_algo


def _load_rsa_cpr(backend):
    """Load the cipher module from the backend."""
    return _load_algo("RSA", backend)


def generate(
    bits: int,
    e: int = 65537,
    *,
    backend: typing.Optional[_Backends] = None,
) -> base.BasePrivateKey:
    """
    Generate a private key with given key modulus ``bits`` and public exponent
    ``e`` (default 65537).
    Recommended size of ``bits`` > 1024.

    Args:
        bits (int): The bit length of the RSA key.
        e (int): The public exponent value. Default is 65537.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        BasePrivateKey: The RSA private key.
    """
    return _load_rsa_cpr(backend).generate(bits, e)


def load_public_key(
    data: typing.ByteString,
    *,
    backend: typing.Optional[_Backends] = None,
) -> base.BasePublicKey:
    """Loads the public key and returns a Key interface.

    Args:
        data (bytes, bytearray):
            The public key (a bytes-like object) to deserialize.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        BasePublicKey: The RSA public key.
    """
    return _load_rsa_cpr(backend).load_public_key(data)


def load_private_key(
    data: typing.ByteString,
    passphrase: typing.Optional[typing.ByteString] = None,
    *,
    backend: typing.Optional[_Backends] = None,
) -> base.BasePrivateKey:
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    `passphrase` must be `None`, otherwise it must be a `bytes` object.

    Args:
        data (bytes, bytearray):
            The private key (a bytes-like object) to deserialize.
        passphrase (bytes, bytearray):
            The passphrase that was used to encrypt the private key.
            ``None`` if the private key was not encrypted.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        BasePrivateKey: The RSA private key.
    """
    return _load_rsa_cpr(backend).load_private_key(data, passphrase)
