"""Interface to ECC signature algorithm and key-exchange."""
from __future__ import annotations

import typing

from ..backends import load_algorithm as _load_algo

if typing.TYPE_CHECKING:
    from .. import base
    from ..backends import Backends


def _load_ecc_cpr(backend):
    """Load the cipher module from the backend."""
    return _load_algo("ECC", backend)


def generate(
    curve: str,
    *,
    backend: typing.Optional[Backends] = None,
) -> base.BaseECCPrivateKey:
    """
    Generate a private key with given curve ``curve``.

    Args:
        curve: The name of the curve to use.

    Keyword Arguments:
        backend: The backend to use. It must be a value from :any:`Backends`.

    Returns:
        An ECC private key.

    Raises:
        ValueError:
            if the curve is not supported by the backend or the name of the
            curve is invalid.
    """
    return _load_ecc_cpr(backend).generate(curve)


def load_public_key(
    data: bytes,
    *,
    curve: typing.Optional[str] = None,
    backend: typing.Optional[Backends] = None,
) -> base.BaseECCPublicKey:
    """Loads the public key and returns a Key interface.

    Args:
        data: The public key (a bytes-like object) to deserialize.
        curve: The name of the curve. Required only for ``SEC1`` keys.

    Keyword Arguments:
        backend: The backend to use. It must be a value from :any:`Backends`.

    Returns:
        An ECC public key.
    """
    return _load_ecc_cpr(backend).load_public_key(
        data,
        curve=curve,
    )


def load_private_key(
    data: bytes,
    passphrase: typing.Optional[bytes] = None,
    *,
    backend: typing.Optional[Backends] = None,
) -> base.BaseECCPrivateKey:
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    `passphrase` must be `None`, otherwise it must be a `bytes` object.

    Args:
        data: The private key (a bytes-like object) to deserialize.
        passphrase:
            The passphrase (in bytes) that was used to encrypt the private key.
            `None` if the key was not encrypted.

    Keyword Arguments:
        backend: The backend to use. It must be a value from `Backends`.

    Returns:
        An ECC Private key.
    """
    return _load_ecc_cpr(backend).load_private_key(data, passphrase)
