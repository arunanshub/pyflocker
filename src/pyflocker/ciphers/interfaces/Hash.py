"""Interface to hashing algorithms."""
from __future__ import annotations

import typing

from ..backends import (
    Backends as _Backends,
    load_algorithm as _load_algo,
)

if typing.TYPE_CHECKING:  # pragma: no cover
    from ..base import BaseHash


def algorithms_available(
    backend: _Backends | None = None,
) -> set[str]:
    """Returns all available hashes supported by backend."""
    if backend is not None:
        return _load_algo("Hash", backend).algorithms_available()

    algos = set()
    for bknd in list(_Backends):
        algos.update(_load_algo("Hash", bknd).algorithms_available())
    return algos


def new(
    hashname: str,
    data: bytes | None = None,
    digest_size: int | None = None,
    *,
    custom: bytes | None = None,
    key: bytes | None = None,
    backend: _Backends | None = None,
) -> BaseHash:
    """
    Instantiate a new hash instance ``hashname`` with initial data ``data``
    (default is empty ``bytes``). The Hash object created by this function can
    be used as the `hash` argument to ``OAEP`` and ``MGF1``.

    Args:
        name: The name of the hash function.
        data: The initial chunk of message to feed to hash.
        digest_size:
            The length of the digest size. Must be supplied if the hash
            function supports it.

    Keyword Arguments:
        custom:
            A customization string. Can be supplied for hash functions
            that support domain separation.
        key:
            A key that is used to compute the MAC. Can be supplied for hash
            functions that support working as cryptographic MAC.
        backend: The backend to use. It must be a value from :any:`Backends`.

    Returns:
        A Hash interface with the given hashing algorithm.

    Raises:
        KeyError: if the hashing function is not supported or invalid.
    """
    hash_ = _load_algo("Hash", backend).new(
        hashname,
        data,
        digest_size=digest_size,
        custom=custom,
        key=key,
    )
    if typing.TYPE_CHECKING:
        assert isinstance(hash_, BaseHash)
    return hash_
