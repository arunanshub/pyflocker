from cryptography.hazmat.primitives.ciphers import (algorithms as algo, Cipher
                                                    as CrCipher)
from cryptography import exceptions as bkx
from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives.poly1305 import Poly1305

from .. import exc, base
from ._symmetric import FileCipherMixin

# we don't have any mode to support
supported = frozenset()


@base.cipher
class ChaCha20Poly1305(base.Cipher):
    def __init__(self, locking, key, nonce):
        if not len(nonce) in (8, 12):
            raise ValueError('A 8 or 12 byte nonce is required')
        if len(nonce) == 8:
            nonce = bytes(4) + nonce

        self._locking = locking
        cipher = CrCipher(
            algo.ChaCha20(
                key,
                (1).to_bytes(4, 'little') + nonce,
            ),
            None,
            defb(),
        )
        if locking:
            self._cipher = cipher.encryptor()
        else:
            self._cipher = cipher.decryptor()

        # generate Poly1305 key (r, s) and instantiate
        cpr = CrCipher(
            algo.ChaCha20(key,
                          bytes(4) + nonce),
            None,
            defb(),
        ).encryptor()
        rs = cpr.update(bytes(32))
        self._auth = Poly1305(rs)

        self._tag = None
        self._updated = False

        self._len_aad = 0
        self._len_ct = 0

        self._update = self._get_update()
        self._update_into = self._get_update_into()

    def authenticate(self, data):
        if self._updated:
            raise TypeError('cannot authenticate data '
                            'after update has been called')
        self._len_aad += len(memoryview(data))
        self._auth.update(data)

    def _pad_aad(self):
        if not self._updated:
            if self._len_aad & 0x0F:
                self._auth.update(bytes(16 - (self._len_aad & 0x0F)))
        self._updated = True

    def update(self, data):
        return self._update(data)

    def update_into(self, data, out):
        self._update_into(data, out)

    def finalize(self, tag=None):
        self._cipher.finalize()
        self._pad_aad()

        if self._len_ct & 0x0F:
            self._auth.update(bytes(16 - (self._len_ct & 0x0F)))

        self._auth.update(self._len_aad.to_bytes(8, 'little'))
        self._auth.update(self._len_ct.to_bytes(8, 'little'))

        if not self._locking:
            try:
                self._auth.verify(tag)
            except bkx.InvalidSignature as e:
                raise exc.DecryptionError from e
        else:
            self._tag = self._auth.finalize()

    def calculate_tag(self):
        if self._locking:
            return self._tag

    def _get_update(self):
        pad = self._pad_aad
        if self._locking:

            def update(data):
                pad()
                res = self._cipher.update(data)
                self._len_ct += len(data)
                self._auth.update(res)
                return res
        else:

            def update(data):
                pad()
                self._len_ct += len(data)
                self._auth.update(data)
                return self._cipher.update(data)

        return update

    def _get_update_into(self):
        pad = self._pad_aad
        if self._locking:

            def update_into(data, out):
                pad()
                self._cipher.update_into(data, out)
                self._len_ct += len(data)
                self._auth.update(out)
        else:

            def update_into(data, out):
                pad()
                self._auth.update(data)
                self._len_ct += len(data)
                self._cipher.update_into(data, out)

        return update_into


@base.cipher
class ChaCha20Poly1305File(FileCipherMixin, ChaCha20Poly1305):
    pass
