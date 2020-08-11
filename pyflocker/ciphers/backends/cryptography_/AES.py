import struct, hmac
from cryptography.hazmat.primitives.ciphers import (Cipher as CrCipher, modes,
                                                    algorithms as algo)
from cryptography.hazmat.primitives import cmac
import cryptography.exceptions as bkx
from cryptography.hazmat.backends import default_backend as defb

from .. import base, Modes as _m

from ._symmetric import (
    AEADCipherWrapper,
    HMACCipherWrapper,
    FileCipherMixin,
    derive_key as _derive_key,
)

supported = {
    _m.MODE_GCM: modes.GCM,
    _m.MODE_EAX: None,  # not defined by backend
    _m.MODE_CTR: modes.CTR,
    _m.MODE_CFB8: modes.CFB8,
    _m.MODE_CFB: modes.CFB,
    _m.MODE_OFB: modes.OFB,
}


def _aes_cipher(key, mode, nonce_or_iv):
    if mode == _m.MODE_EAX:
        return _EAX(key, nonce_or_iv)
    return CrCipher(algo.AES(key), supported[mode](nonce_or_iv), defb())


@base.cipher
class AEAD(AEADCipherWrapper, base.Cipher):
    def __init__(self, locking, key, mode, *args, **kwargs):
        self._cipher = _aes_cipher(key, mode, *args, **kwargs)
        self._locking = locking
        super().__init__()


class AEADFile(FileCipherMixin, AEAD):
    pass


def strxor(x, y):
    """ XOR two byte strings """
    return bytes([ix ^ iy for ix, iy in zip(x, y)])


class _EAX:
    """Pseudo pyca/cryptography style cipher for EAX mode."""
    def __init__(self, key, nonce, mac_len=16):
        self._mac_len = mac_len
        self._omac = [cmac.CMAC(algo.AES(key), defb()) for i in range(3)]

        # update the CMACs
        [
            self._omac[i].update(
                bytes(1) * (algo.AES.block_size // 8 - 1) +
                struct.pack('B', i)) for i in range(3)
        ]

        self._omac[0].update(nonce)
        self._auth = self._omac[1]

        # create a cache since cryptography allows us to calculate tag
        # only once... why...
        self._omac_cache = []
        self._omac_cache.append(self._omac[0].finalize())

        self._cipher = CrCipher(
            algo.AES(key),
            modes.CTR(self._omac_cache[0]),
            defb(),
        )

        self._update = None
        self._update_into = None
        self._updated = False
        self._tag = None

    @property
    def _ctx(self):
        """The Cipher context used by the backend.
        Maintains compatibility across pyca/cryptography style
        cipher instances.
        """
        return self._cipher._ctx

    def authenticate_additional_data(self, data):
        if self._updated:
            raise ValueError
        self._auth.update(data)

    def encryptor(self):
        """Create a pseudo-encryptor context.

        Pseudo in the sense that, pyca/cryptography uses a encryption
        or decryption context, but we replace the object variable.

        Replaces the variables `_update` and `_update_into`
        with suitable functions.
        """
        self._cipher = self._cipher.encryptor()

        hashup = self._omac[2].update
        cipherup1 = self._cipher.update
        cipherup2 = self._cipher.update_into

        def update(data):
            ctxt = cipherup1(data)
            hashup(ctxt)
            return ctxt

        def update_into(data, out):
            cipherup2(data, out)
            hashup(bytes(out[:-15]))  # bytes obj only

        self._update = update
        self._update_into = update_into
        return self

    def decryptor(self):
        """Create a pseudo-encryptor context.

        Pseudo in the sense that, pyca/cryptography uses a encryption
        or decryption context, but we replace the object variable.

        Replaces the variables `_update` and `_update_into`
        with suitable functions.
        """
        self._cipher = self._cipher.decryptor()

        hashup = self._omac[2].update
        cipherup1 = self._cipher.update
        cipherup2 = self._cipher.update_into

        def update(ctxt):
            hashup(ctxt)
            data = cipherup1(ctxt)
            return data

        def update_into(data, out):
            hashup(bytes(data))  # bytes obj only
            cipherup2(data, out)

        self._update = update
        self._update_into = update_into
        return self

    def update(self, data):
        self._updated = True
        return self._update(data)

    def update_into(self, data, out):
        self._updated = True
        self._update_into(data, out)

    def finalize(self):
        """Finalizes the cipher. It is not affected by the number of
        calls to it."""
        if not self._tag:
            tag = bytes(algo.AES.block_size // 8)
            for i in range(3):
                try:
                    tag = strxor(tag, self._omac_cache[i])
                except IndexError:
                    self._omac_cache.append(self._omac[i].finalize())
                    tag = strxor(tag, self._omac_cache[i])
            self._tag = tag[:self._mac_len]

    def finalize_with_tag(self, tag):
        self.finalize()
        if not hmac.compare_digest(tag, self._tag):
            raise bkx.InvalidTag

    @property
    def tag(self):
        return self._tag


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
        hkey = None
        if hashed:
            # derive the keys (length same as of the original key)
            key, hkey = _derive_key(
                master_key=key,
                dklen=len(key),
                hashalgo=digestmod,
                salt=iv_or_nonce,
            )

        self._cipher = _aes_cipher(key, mode, iv_or_nonce)
        # for HMAC mixin
        super().__init__(
            key=hkey,
            hashed=hashed,
            digestmod=digestmod,
            rand=iv_or_nonce,
        )


class NonAEADFile(FileCipherMixin, NonAEAD):
    pass
