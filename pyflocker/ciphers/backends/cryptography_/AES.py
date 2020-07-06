from cryptography.hazmat.primitives.ciphers import (Cipher as CrCipher, modes,
                                                    algorithms as algo)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend as defb

from .. import base, Modes as _m

from ._symmetric import (AEADCipherWrapper, HMACCipherWrapper, FileCipherMixin)
from ._hashes import hashes as _hashes

supported = {
    _m.MODE_GCM: modes.GCM,
    _m.MODE_CTR: modes.CTR,
    _m.MODE_CFB8: modes.CFB8,
    _m.MODE_CFB: modes.CFB,
    _m.MODE_OFB: modes.OFB,
}


def _aes_cipher(key, mode, nonce_or_iv):
    return CrCipher(algo.AES(key), supported[mode](nonce_or_iv), defb())


@base.cipher
class AEAD(AEADCipherWrapper, base.Cipher):
    def __init__(self, locking, key, mode, *args, **kwargs):
        self._cipher = _aes_cipher(key, mode, *args, **kwargs)
        self._locking = locking
        super().__init__()


class AEADFile(FileCipherMixin, AEAD):
    pass


def _derive_key(master_key, dklen, hashalgo, salt, info, num_keys):
    kdf = HKDF(
        _hashes[hashalgo](),
        num_keys * dklen,
        salt,
        info,
        defb(),
    )
    drkey = kdf.derive(master_key)
    keys = [drkey[idx:idx + dklen]
            for idx in range(0, dklen * num_keys, dklen)]
    return keys


@base.cipher
class NonAEAD(HMACCipherWrapper, base.Cipher):
    def __init__(self,
                 locking,
                 key,
                 mode,
                 iv_or_nonce,
                 *,
                 hashed=False,
                 digestmod='sha256'):
        self._locking = locking
        if hashed:

            # derive the keys (length same as of the original key)
            key, hkey = _derive_key(
                master_key=key,
                dklen=len(key),
                hashalgo=digestmod,
                salt=_randpart,
                info=b"auth-key",
                num_keys=2,
            )
        else:
            hkey, _randpart = None, None

        self._cipher = _aes_cipher(key, mode, iv_or_nonce)
        # for HMAC mixin
        super().__init__(
            key=hkey,
            hashed=hashed,
            digestmod=digestmod,
            rand=_randpart,
        )


class NonAEADFile(FileCipherMixin, NonAEAD):
    pass
