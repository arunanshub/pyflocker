"""Interface to hashing algorithms."""

import typing

from ..backends import Backends as _Backends
from ..backends import load_algorithm as _load_algo
from ..base import BaseHash as _BaseHash


def algorithms_available(backend: _Backends = None) -> typing.Set[str]:
    """Returns all available hashes supported by backend."""
    if backend is not None:
        return _load_algo("Hash", backend).algorithms_available()

    algos = set()
    for bknd in list(_Backends):
        algos.update(_load_algo("Hash", bknd).algorithms_available())
    return algos


def new(
    hashname: str,
    data: typing.ByteString = b"",
    digest_size: typing.Optional[int] = None,
    *,
    backend: typing.Optional[_Backends] = None,
) -> _BaseHash:
    """
    Instantiate a new hash instance ``hashname`` with initial
    data ``data`` (default is empty ``bytes``).
    The Hash object created by this function can be used as
    the `hash` argument to ``OAEP`` and ``MGF1``.

    Args:
        hashname (str): Name of the hashing function to use.
        data (bytes, bytearray, memoryview):
            Initial data to pass to hashing function.
        digest_size (int):
            The length of the digest from the hash function.
            Required for ``Blake`` and ``Shake``.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`, None):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        BaseHash: A Hash interface with the given hashing algorithm.

    Raises:
        KeyError: if the hashing function is not supported or invalid.
    """
    return _load_algo("Hash", backend).new(
        hashname,
        data,
        digest_size=digest_size,
    )
