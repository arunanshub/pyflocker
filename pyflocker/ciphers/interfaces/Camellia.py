"""Interface to Camellia cipher"""


from .. import load_cipher as _load_cpr
from .. import Backends


def _cml_cipher_from_mode(mode, bknd):
    if mode not in bknd.supported.keys():
        raise NotImplementedError(
            "backend does not support this mode.")
    return bknd.NonAEAD 


def new(file, locking, key, mode, *args, backend=Backends.CRYPTOGRAPHY, **kwargs):
    cpr = _load_cpr("Camellia", backend)
    return _cml_cipher_from_mode(mode, cpr)(
        file, locking, key, mode, *args, **kwargs)

