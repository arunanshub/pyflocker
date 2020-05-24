from cryptography.hazmat.primitives.ciphers import (
    Cipher as CrCipher, modes, algorithms as algo)
from cryptography.hazmat.backends import default_backend as defb

from ..import base, Modes as _m

from ._symmetric import (
    AEADCipherWrapper,
    HMACCipherWrapper,
    FileCipherMixin)


supported = {
    _m.MODE_GCM : modes.GCM,
    _m.MODE_CTR : modes.CTR,
    _m.MODE_CFB : modes.CFB,
    _m.MODE_OFB : modes.OFB,
}


def _aes_cipher(key, mode, *args, **kwargs):
    return CrCipher(algo.AES(key),
        supported[mode](*args, **kwargs), defb())


@base.cipher
class AEAD(AEADCipherWrapper, base.Cipher):

    def __init__(self, locking, key, mode,
                 *args, **kwargs):
        self._cipher = _aes_cipher(key, mode,
            *args, **kwargs)
        self._locking = locking
        super().__init__()


class AEADFile(FileCipherMixin, AEAD):
    pass


@base.cipher
class NonAEAD(HMACCipherWrapper, base.Cipher):
    def __init__(self, locking, key, mode,
                 *args,
                 hashed=True, digestmod='sha256',
                 **kwargs):

        self._locking = locking
        self._cipher = _aes_cipher(key, mode,
            *args, **kwargs)
        # for HMAC mixin
        super().__init__(key=key, hashed=hashed,
            digestmod=digestmod,)


class NonAEADFile(FileCipherMixin, NonAEAD):
    pass

