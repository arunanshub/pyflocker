from .. import load_cipher as _load_cpr


def new(locking, key, nonce, *,
        file=None, backend=None):
    cpr = _load_cpr("ChaCha20", backend)
    if file:
        _cpr = cpr.ChaCha20Poly1305File
        return _cpr(locking, key, nonce, file=file)
    else:
        _cpr = cpr.ChaCha20Poly1305
        return _cpr(locking, key, nonce)

