from cryptography.hazmat.primitives.ciphers import algorithms as algo, Cipher as CrCipher
from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives.poly1305 import Poly1305

from cryptography import exceptions as bkx

from functools import partial
from .. import exc, base
from .. import _utils


# we don't have any mode to support
supported = frozenset()


@base.cipher
class ChaCha20Poly1305(base.Cipher):

    def __init__(self, file, locking, key, nonce):
        self._locking = locking
        self._file = file
 
        # no mode taken
        self._hasher = Poly1305(key)
        _cipher = CrCipher(algo.ChaCha20(key, nonce), None, defb())
        self._cipher = (_cipher.encryptor()
                        if locking
                        else _cipher.decryptor())
        
        self._cipher.tag = None
        # for authenticate method
        self._updated = False

    def update(self, blocksize=16384):
        self._updated = True
        data = self._file.read(blocksize)
        if data:
            if not self._locking:
                self._hasher.update(data)
                return self._cipher.update(data)
            else:
                data = self._cipher.update(data)
                self._hasher.update(data)
                return data

    def authenticate(self, data):
        if self._updated:
            raise TypeError(
                "cannot authenticate data after update is called") from None
        self._hasher.update(data)

    def update_into(self, file, tag=None, blocksize=16384):
        if not self._locking and tag is None:
            raise ValueError("tag is required for decryption")
        rbuf = memoryview(bytearray(blocksize))
        update = _utils.updater(
            self._locking,
            self._cipher.update,
            self._hasher.update,)

        reads = iter(partial(self._file.readinto, rbuf), 0)
        write = file.write

        for i in reads:
            if i < blocksize:
                rbuf = rbuf[:i]
            update(rbuf, rbuf)
            write(rbuf)
        self.finalize(tag)

    def finalize(self, tag=None):
        if not self._locking:
            try:
                self._hasher.verify(tag)
            except bkx.InvalidSignature:
                raise exc.DecryptionError from None

    def calculate_tag(self):
        if self._locking:
            if not self._cipher.tag:
                self._cipher.tag = self._hasher.finalize()
            return self._cipher.tag

