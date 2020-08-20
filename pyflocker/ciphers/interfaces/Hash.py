"""Interface to hashing algorithms."""

from .. import load_cipher as _load_cpr


def new(hashname, data=b'', digest_size=None, *, backend=None):
    """
    Instantiate a new hash instance `hashname` with initial
    data `data` (default is empty `bytes`).
    The Hash object created by this function can be used as
    the `hash` argument to OAEP and MGF1.

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
