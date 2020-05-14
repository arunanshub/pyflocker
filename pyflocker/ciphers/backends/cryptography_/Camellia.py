from cryptography.hazmat.primitives.ciphers import (Cipher,
        algorithms as algo, modes)
from cryptography.hazmat.backends import default_backend as defb
import hmac

from .. import base, exc, Modes as _m
from .AES import NonAEAD as _NonAEAD


supported = {
    _m.MODE_CFB : modes.CFB,
    _m.MODE_CTR : modes.CTR,
    _m.MODE_OFB : modes.OFB,
}


class NonAEAD(_NonAEAD):

    def __init__(self, file, locking, key, mode, *args, **kwargs):

        digestmod = kwargs.pop('digestmod', 'sha256')
        self._file = file
        self._locking = locking

        _cipher = Cipher(algo.Camellia(key), supported[mode](*args, **kwargs), defb())
        self._cipher = _cipher.encryptor() if locking else _cipher.decryptor()

        self._hasher = hmac.new(key, digestmod=digestmod)

        # for authenticate method
        self._updated = False

