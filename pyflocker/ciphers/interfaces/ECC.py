"""Interface to ECC signature algorithm and key-exchange."""

from ..backends import load_algorithm as _load_algo


def _load_ecc_cpr(backend):
    """Load the cipher module from the backend."""
    return _load_algo("ECC", backend)


def generate(curve, *, backend=None):
    """
    Generate a private key with given curve `curve`.

    Args:
        curve (str): The name of the curve to use.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        :any:`BasePrivateKey`: An `ECCPrivateKey` interface.

    Raises:
        KeyError:
            if the curve is not supported by the backend or the name of the
            curve is invalid.
    """
    return _load_ecc_cpr(backend).ECCPrivateKey(curve)


def load_public_key(data, *, edwards=None, backend=None):
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
        :any:`BasePublicKey`: An `ECCPublicKey` interface.
    """
    kwargs = dict()
    if len(data) == 32:
        kwargs = dict(edwards=edwards)
    return _load_ecc_cpr(backend).ECCPublicKey.load(data, **kwargs)


def load_private_key(data, passphrase=None, *, edwards=None, backend=None):
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    `passphrase` must be `None`, otherwise it must be a `bytes` object.

    Args:
        data (bytes, bytearray):
            The private key (a bytes-like object) to deserialize.
        password (bytes, bytearray):
            The password (in bytes) that was used to encrypt the
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
        :any:`BasePrivateKey`: An ECCPrivateKey interface.
    """
    kwargs = dict()
    if len(data) == 32:
        kwargs = dict(edwards=edwards)
    return _load_ecc_cpr(backend).ECCPrivateKey.load(
        data,
        passphrase,
        **kwargs,
    )
