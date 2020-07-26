try:
    from Cryptodome.Cipher import AES
except ModuleNotFoundError:
    from Crypto.Cipher import AES

from .. import base, Modes as _m
from ._symmetric import (
    FileCipherMixin,
    AEADCipherWrapper,
    HMACCipherWrapper,
    derive_key as _derive_key,
)

supported = {
    # classic modes
    _m.MODE_CTR: AES.MODE_CTR,
    _m.MODE_CFB: AES.MODE_CFB,
    _m.MODE_CFB8: AES.MODE_CFB,  # compat with pyca/cryptography
    _m.MODE_OFB: AES.MODE_OFB,

    # AEAD modes
    _m.MODE_GCM: AES.MODE_GCM,
    _m.MODE_EAX: AES.MODE_EAX,
    _m.MODE_SIV: AES.MODE_SIV,
    _m.MODE_CCM: AES.MODE_CCM,
    _m.MODE_OCB: AES.MODE_OCB,
}


def _aes_cipher(key, mode, iv_or_nonce):
    args = (iv_or_nonce, )
    kwargs = dict()

    if mode == _m.MODE_CFB:
        # compat with pyca/cryptography's CFB(...) mode
        kwargs = dict(segment_size=128)
    elif mode == _m.MODE_CTR:
        kwargs = dict(
            # initial value of Cryptodome is nonce for pyca/cryptography
            initial_value=int.from_bytes(iv_or_nonce, 'big'),
            nonce=b'',
        )
        args = ()

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
                 iv_or_nonce,
                 *,
                 hashed=False,
                 digestmod='sha256'):
        self._locking = locking
        hkey = None

        if hashed:
            # derive the keys (length same as of the original key)
            key, hkey = _derive_key(key, len(key), digestmod, iv_or_nonce)

        self._cipher = _aes_cipher(key, mode, iv_or_nonce)
        super().__init__(
            key=hkey,
            hashed=hashed,
            digestmod=digestmod,
            rand=iv_or_nonce,
        )


class NonAEADFile(FileCipherMixin, NonAEAD):
    pass


# AES ciphers that needs special attention
@base.cipher
class AEADOneShot(AEAD):
    """Implements AES modes that do not support
    gradual encryption and decryption, which means,
    everything has to be done in one go (one shot)
    """
    def update_into(self, data, out, tag=None):
        if self._locking:
            dat = self._cipher.encrypt_and_digest(data, out)[0]
            self.finalize()
            return dat

        if tag is None:
            raise ValueError('tag is required for decryption')
        crpup = self._cipher.decrypt_and_verify
        try:
            dat = crpup(data, tag, out)
        except ValueError:
            dat = None
        self.finalize(tag)
        return dat

    def update(self, data, tag=None):
        return self.update_into(data, out=None, tag=tag)
