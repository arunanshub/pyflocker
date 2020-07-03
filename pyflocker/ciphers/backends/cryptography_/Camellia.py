from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms as algo,
                                                    modes)
from cryptography.hazmat.backends import default_backend as defb

from .. import base, exc, Modes as _m
from ._symmetric import HMACCipherWrapper, FileCipherMixin

supported = {
    _m.MODE_CFB: modes.CFB,
    _m.MODE_CTR: modes.CTR,
    _m.MODE_OFB: modes.OFB,
}


@base.cipher
class Camellia(HMACCipherWrapper, base.Cipher):
    def __init__(self,
                 locking,
                 key,
                 mode,
                 *args,
                 hashed=True,
                 digestmod='sha256',
                 **kwargs):
        self._cipher = Cipher(algo.Camellia(key), supported[mode](*args,
                                                                  **kwargs),
                              defb())
        self._locking = locking
        super().__init__(key=key, hashed=hashed, digestmod=digestmod)


class CamelliaFile(FileCipherMixin, Camellia):
    pass
