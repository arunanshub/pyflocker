"""Interface to DH key exchange"""
from __future__ import annotations

import typing
from typing import TYPE_CHECKING

from ..backends import Backends as _Backends
from ..backends import load_algorithm as _load_algo

if TYPE_CHECKING:  # pragma: no cover
    from .. import base


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
        key_size: The bit length of the prime modulus.
        g: The value to use as a generator value. Default is 2.

    Keyword Arguments:
        backend:
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
        p: The prime modulus ``p``.
        g: The generator.
        q: ``p`` subgroup order value.

    Keyword Arguments:
        backend: The backend to use. It must be a value from :any:`Backends`.

    Returns:
        A DH key exchange paramenter object.
    """
    return _load_dhe(backend).load_from_parameters(p, g, q)


def load_parameters(
    data: bytes,
    *,
    backend=_Backends.CRYPTOGRAPHY,
) -> base.BaseDHParameters:
    """Deserialize the DH parameters and load a parameter object.

    Args:
        data: Serialized DH Parameter.

    Keyword Arguments:
        backend: The backend to use. It must be a value from :any:`Backends`.

    Returns:
        A DHE parameter object.
    """
    return _load_dhe(backend).load_parameters(data)


def load_public_key(
    data: bytes,
    *,
    backend: _Backends = _Backends.CRYPTOGRAPHY,
) -> base.BaseDHPublicKey:
    """Loads the public key and returns a Key interface.

    Args:
        data: The public key (a bytes-like object) to deserialize.

    Keyword Arguments:
        backend: The backend to use. It must be a value from :any:`Backends`.

    Returns:
        An public key object.
    """
    return _load_dhe(backend).load_public_key(data)


def load_private_key(
    data: bytes,
    passphrase: typing.Optional[bytes] = None,
    *,
    backend: _Backends = _Backends.CRYPTOGRAPHY,
) -> base.BaseDHPrivateKey:
    """Loads the private key.

    Args:
        data: The private key (a bytes-like object) to deserialize.
        passphrase:
            The passphrase (in bytes) that was used to encrypt the private key.
            ``None`` if the key was not encrypted.

    Keyword Arguments:
        backend:
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        A private key object.
    """
    return _load_dhe(backend).load_private_key(data, passphrase)
