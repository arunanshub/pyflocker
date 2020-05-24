"""Interface to Camellia cipher"""


from .. import load_cipher as _load_cpr
from .. import Backends


def _cml_cipher_from_mode(mode, bknd, hasfile):
    if mode not in bknd.supported.keys():
        raise NotImplementedError(
            "backend does not support this mode.")
    if not hasfile:
        return bknd.Camellia
    return bknd.CamelliaFile


def new(locking, key, mode, *args, file=None,
        backend=Backends.CRYPTOGRAPHY, **kwargs):
    cpr = _load_cpr("Camellia", backend)
    _cpr = _cml_cipher_from_mode(
        mode, cpr, file is not None)
    if file:
        return _cpr(locking, key, mode, *args, file=file, **kwargs)
    return _cpr(locking, key, mode, *args, **kwargs)

