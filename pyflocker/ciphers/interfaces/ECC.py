"""Interface to ECC signature algorithm and key-exchange."""
import typing

from ..backends import Backends as _Backends
from ..backends import load_algorithm as _load_algo


def _load_ecc_cpr(backend):
    """Load the cipher module from the backend."""
    return _load_algo("ECC", backend)


def generate(curve: str, *, backend: typing.Optional[_Backends] = None):
    """
    Generate a private key with given curve ``curve``.

    Args:
        curve (str): The name of the curve to use.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        BasePrivateKey: An ECC private key.

    Raises:
        ValueError:
            if the curve is not supported by the backend or the name of the
            curve is invalid.
    """
    return _load_ecc_cpr(backend).generate(curve)


def load_public_key(
    data: typing.ByteString,
    *,
    edwards: bool = True,
    backend: typing.Optional[_Backends] = None,
):
    """Loads the public key and returns a Key interface.

    Args:
        data (bytes, bytearray):
            The public key (a bytes-like object) to deserialize.

    Keyword Arguments:
        edwards (bool, NoneType):
            Whether the `Raw` encoded key of length 32 bytes
            must be imported as an `Ed25519` key or `X25519` key.

            If `True`, the key will be imported as an `Ed25519` key,
            otherwise an `X25519` key.
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        BasePublicKey: An ECC public key.
    """
    kwargs = dict()
    if len(data) == 32:
        if backend == _Backends.CRYPTOGRAPHY:
            kwargs = dict(edwards=edwards)
    return _load_ecc_cpr(backend).load_public_key(data, **kwargs)


def load_private_key(
    data: typing.ByteString,
    passphrase: typing.Optional[typing.ByteString] = None,
    *,
    edwards: bool = True,
    backend: typing.Optional[_Backends] = None,
):
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    `passphrase` must be `None`, otherwise it must be a `bytes` object.

    Args:
        data (bytes, bytearray):
            The private key (a bytes-like object) to deserialize.
        passphrase (bytes, bytearray):
            The passphrase (in bytes) that was used to encrypt the
            private key. `None` if the key was not encrypted.

    Keyword Arguments:
        edwards (bool, NoneType):
            Whether the `Raw` encoded key of length 32 bytes
            must be imported as an `Ed25519` key or `X25519` key.

            If `True`, the key will be imported as an `Ed25519` key,
            otherwise an `X25519` key.
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from `Backends`.

    Returns:
        BasePrivateKey: An ECCPrivateKey interface.
    """
    kwargs = dict()
    if len(data) == 32:
        if backend == _Backends.CRYPTOGRAPHY:
            kwargs = dict(edwards=edwards)
    return _load_ecc_cpr(backend).load_private_key(
        data,
        passphrase,
        **kwargs,
    )
