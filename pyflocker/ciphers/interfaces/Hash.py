"""Interface to hashing algorithms.
These are currently limited to SHA-* algorithms."""

from .. import load_cipher as _load_cpr


def new(hashname, data=b'', digest_size=None, *, backend=None):
    """
    Instantiate a new hash instance `hashname` with initial
    data `data` (default is empty `bytes`).

    When there is a requirement of a particular hash by a cipher,
    you must choose the hash algorithm from the correct backend,
    by passing in the backend keyword.

    Args:
        hashname: Name of the hashing function to use.
        data: Initial data to pass to hashing function.
        digest_size:
            The length of the digest from the hash function.
            Required for Blake and Shake.

    Kwargs:
        backend:
            The backend to use. It must be a value from `Backends`.

    Returns:
        A Hash interface with the given hashing algorithm.

    Raises:
        KeyError if the hashing function is not supported.
    """
    return _load_cpr('Hash', backend).Hash(
        hashname,
        data,
        digest_size=digest_size,
    )
