from .. import load_cipher as _load_cpr


def new(hashname, data=b'', *, backend=None):
    """
    Instantiate a new hash instance `hashname` with initial
    data `data` (default is empty `bytes`).

    `backend` must be an attribute of `Backends`.
    """
    return _load_cpr('Hash', backend).Hash(hashname, data)
