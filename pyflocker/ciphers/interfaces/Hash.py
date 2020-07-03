from .. import load_cipher as _load_cpr


def new(hashname, data=b'', *, backend=None):
    return _load_cpr('Hash', backend).Hash(hashname, data)
