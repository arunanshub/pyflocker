from functools import partial
import hmac

try:
    from Cryptodome.Cipher import AES
except ModuleNotFoundError:
    from Crypto.Cipher import AES

from .. import exc, base, Modes as _m
from ._symmetric import (FileCipherMixin, AEADCipherWrapper, HMACCipherWrapper)

supported = {
    # classic modes
    _m.MODE_CTR: AES.MODE_CTR,
    _m.MODE_CFB: AES.MODE_CFB,
    _m.MODE_OFB: AES.MODE_OFB,

    # AEAD modes
    _m.MODE_GCM: AES.MODE_GCM,
    _m.MODE_EAX: AES.MODE_EAX,
    _m.MODE_SIV: AES.MODE_SIV,
    _m.MODE_CCM: AES.MODE_CCM,
    _m.MODE_OCB: AES.MODE_OCB,
}


def _aes_cipher(key, mode, *args, **kwargs):
    return AES.new(key, supported[mode], *args, **kwargs)


@base.cipher
class AEAD(AEADCipherWrapper, base.Cipher):
    """Cipher wrapper for AEAD supported modes"""
    def __init__(self, locking, key, mode, *args, **kwargs):
        self._cipher = _aes_cipher(key, mode, *args, **kwargs)
        self._locking = locking
        super().__init__()


class AEADFile(FileCipherMixin, AEAD):
    pass


@base.cipher
class NonAEAD(HMACCipherWrapper, base.Cipher):
    """Cipher wrapper for classic modes of AES"""
    def __init__(self,
                 locking,
                 key,
                 mode,
                 *args,
                 hashed=True,
                 digestmod='sha256',
                 **kwargs):
        self._cipher = _aes_cipher(key, mode, *args, **kwargs)
        self._locking = locking
        super().__init__(key=key, hashed=hashed, digestmod=digestmod)


class NonAEADFile(FileCipherMixin, NonAEAD):
    pass


# AES ciphers that needs special attention
class AEADOneShot(AEAD):
    """Implements AES modes that does not support
    gradual encryption and decryption, which means,
    everything has to be done in one go (one shot)
    """
    def update_into(self, data, out, tag=None):
        if self._locking:
            return self._cipher.encrypt_and_digest(data, out)[0]
            self.finalize()
        else:
            if tag is None:
                raise ValueError('tag required')
            crpup = self._cipher.decrypt_and_verify
        try:
            return crpup(data, tag, out)
        except ValueError:
            pass
        self.finalize(tag)

    def update(self, data, tag=None):
        self.update_into(data, out=None, tag=tag)
