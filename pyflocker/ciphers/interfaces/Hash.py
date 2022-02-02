"""Interface to hashing algorithms."""

import typing

from ..backends import Backends as _Backends
from ..backends import load_algorithm as _load_algo

if typing.TYPE_CHECKING:
    from ..base import BaseHash


def algorithms_available(
    backend: typing.Optional[_Backends] = None,
) -> typing.Set[str]:
    """Returns all available hashes supported by backend."""
    if backend is not None:
        return _load_algo("Hash", backend).algorithms_available()

    algos = set()
    for bknd in list(_Backends):
        algos.update(_load_algo("Hash", bknd).algorithms_available())
    return algos


def new(
    hashname: str,
    data: typing.Optional[bytes] = None,
    digest_size: typing.Optional[int] = None,
    *,
    custom: typing.Optional[bytes] = None,
    key: typing.Optional[bytes] = None,
    backend: typing.Optional[_Backends] = None,
) -> "BaseHash":
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

    Keyword Args:
        custom:
            A customization string. Can be supplied for hash functions
            that support domain separation.
        key:
            A key that is used to compute the MAC. Can be supplied for hash
            functions that support working as cryptographic MAC.
        backend: The backend to use. It must be a value from :any:`Backends`.

    Returns:
        BaseHash: A Hash interface with the given hashing algorithm.

    Raises:
        KeyError: if the hashing function is not supported or invalid.
    """
    return _load_algo("Hash", backend).new(
        hashname,
        data,
        digest_size=digest_size,
        custom=custom,
        key=key,
    )
