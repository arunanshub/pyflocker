from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms as algo,
                                                    modes)
from cryptography.hazmat.backends import default_backend as defb

from .. import base, Modes as _m
from ._symmetric import (
    HMACCipherWrapper,
    FileCipherMixin,
    derive_key as _derive_key,
)

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
                 iv_or_nonce,
                 *,
                 hashed=False,
                 digestmod='sha256'):
        if hashed:
            # derive the keys (length same as of the original key)
            key, hkey = _derive_key(
                master_key=key,
                dklen=len(key),
                hashalgo=digestmod,
                salt=iv_or_nonce,
            )
        else:
            hkey = None

        self._cipher = Cipher(
            algo.Camellia(key),
            supported[mode](iv_or_nonce),
            defb(),
        )
        self._locking = locking
        super().__init__(
            key=hkey,
            hashed=hashed,
            digestmod=digestmod,
            rand=iv_or_nonce,
        )


class CamelliaFile(FileCipherMixin, Camellia):
    pass
