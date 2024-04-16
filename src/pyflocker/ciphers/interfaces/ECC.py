"""Interface to ECC signature algorithm and key-exchange."""

from __future__ import annotations

import typing

from pyflocker.ciphers.backends import load_algorithm as _load_algo

if typing.TYPE_CHECKING:
    from types import ModuleType

    from pyflocker.ciphers import base
    from pyflocker.ciphers.backends import Backends


def _load_ecc_cpr(backend: Backends | None) -> ModuleType:
    """Load the cipher module from the backend."""
    return _load_algo("ECC", backend)


def generate(
    curve: str,
    *,
    backend: Backends | None = None,
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
    curve: str | None = None,
    backend: Backends | None = None,
) -> base.BaseECCPublicKey:
    """Loads the public key and returns a Key interface.

    Args:
        data: The public key (a bytes-like object) to deserialize.
        curve:
            The name of the curve. Required only for ``SEC1`` and ``Raw``
            keys.

    Keyword Arguments:
        backend: The backend to use. It must be a value from :any:`Backends`.

    Returns:
        An ECC public key.
    """
    return _load_ecc_cpr(backend).load_public_key(data, curve=curve)


def load_private_key(
    data: bytes,
    passphrase: bytes | None = None,
    *,
    curve: str | None = None,
    backend: Backends | None = None,
) -> base.BaseECCPrivateKey:
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    `passphrase` must be `None`, otherwise it must be a `bytes` object.

    Args:
        data: The private key (a bytes-like object) to deserialize.
        passphrase:
            The passphrase (in bytes) that was used to encrypt the private key.
            `None` if the key was not encrypted.
        curve: The name of the curve. Required only for ``Raw`` keys.

    Keyword Arguments:
        backend: The backend to use. It must be a value from `Backends`.

    Returns:
        An ECC Private key.
    """
    return _load_ecc_cpr(backend).load_private_key(
        data,
        passphrase,
        curve=curve,
    )
