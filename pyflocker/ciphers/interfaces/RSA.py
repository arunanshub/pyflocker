"""Interface to RSA cipher and signature algorithm"""
from __future__ import annotations

import typing
from typing import TYPE_CHECKING

from ..backends import load_algorithm as _load_algo

if TYPE_CHECKING:  # pragma: no cover
    from types import ModuleType

    from ..backends import Backends
    from ..base import BaseRSAPrivateKey, BaseRSAPublicKey


def _load_rsa(backend: Backends) -> ModuleType:
    """Load the cipher module from the backend."""
    return _load_algo("RSA", backend)


def generate(
    bits: int,
    e: int = 65537,
    *,
    backend: typing.Optional[Backends] = None,
) -> BaseRSAPrivateKey:
    """
    Generate a private key with given key modulus ``bits`` and public exponent
    ``e`` (default 65537). Recommended size of ``bits`` > 1024.

    Args:
        bits: The bit length of the RSA key.
        e: The public exponent value. Default is 65537.

    Keyword Arguments:
        backend: The backend to use. It must be a value from :any:`Backends`.

    Returns:
        The RSA private key.
    """
    return _load_rsa(backend).generate(bits, e)


def load_public_key(
    data: bytes,
    *,
    backend: typing.Optional[Backends] = None,
) -> BaseRSAPublicKey:
    """Loads the public key and returns a Key interface.

    Args:
        data: The public key (a bytes-like object) to deserialize.

    Keyword Arguments:
        backend: The backend to use. It must be a value from :any:`Backends`.

    Returns:
        The RSA public key.
    """
    return _load_rsa(backend).load_public_key(data)


def load_private_key(
    data: bytes,
    passphrase: typing.Optional[bytes] = None,
    *,
    backend: typing.Optional[Backends] = None,
) -> BaseRSAPrivateKey:
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization, `passphrase`
    must be `None`, otherwise it must be a `bytes` object.

    Args:
        data: The private key (a bytes-like object) to deserialize.
        passphrase:
            The passphrase that was used to encrypt the private key. ``None``
            if the private key was not encrypted.

    Keyword Arguments:
        backend: The backend to use. It must be a value from :any:`Backends`.

    Returns:
        The RSA private key.
    """
    return _load_rsa(backend).load_private_key(data, passphrase)
