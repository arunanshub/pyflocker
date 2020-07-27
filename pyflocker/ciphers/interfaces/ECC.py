"""Interface to ECC signature algorithm and key-exchange."""

from .. import load_cipher as _load_cpr


def _load_ecc_cpr(backend):
    """Load the cipher module from the backend."""
    return _load_cpr('ECC', backend)


def generate(curve, *, backend=None):
    """
    Generate a private key with given curve `curve`.

    Args:
        curve: The name of the curve to use.

    Kwargs:
        backend: The backend to use. It must be a value from `Backends`.

    Returns:
        An ECC private key interface.

    Raises:
        `KeyError` if the curve is not supported by the backend or
        the name of the curve is invalid.
    """
    return _load_ecc_cpr(backend).ECCPrivateKey(curve)


def load_public_key(data, *, backend=None):
    """Loads the public key and returns a Key interface.

    Args:
        data: The public key (a bytes-like object) to deserialize.

    Kwargs:
        backend: The backend to use. It must be a value from `Backends`.

    Returns:
        An ECCPublicKey interface.
    """
    return _load_ecc_cpr(backend).ECCPublicKey.load(data)


def load_private_key(data, passphrase=None, *, backend=None):
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
        An ECCPrivateKey interface.
    """
    return _load_ecc_cpr(backend).ECCPrivateKey.load(data, passphrase)
