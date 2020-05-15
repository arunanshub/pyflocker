from .. import load_cipher as _load_cpr


def new(file, locking, key, nonce, backend=None):
    cpr = _load_cpr("ChaCha20", backend)
    return cpr.ChaCha20Poly1305(file, locking, key, nonce)

