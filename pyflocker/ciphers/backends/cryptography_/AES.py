from cryptography.hazmat.primitives.ciphers import (
    Cipher as CrCipher, modes, algorithms as algo)
from cryptography.hazmat.backends import default_backend as defb
import cryptography.exceptions as bkx
from functools import partial
import hmac

from .. import exc, base, load_interface as _if
from .. import _utils


# load implementation counterpart
_m = _if("AES")


supported = {
    _m.MODE_GCM : modes.GCM,
    _m.MODE_CTR : modes.CTR,
    _m.MODE_CFB : modes.CFB,
    _m.MODE_OFB : modes.OFB,
}


@base.cipher
class AESAEAD(base.Cipher):

    def __init__(self, file, locking, key, mode, *args, **kwargs):
        self._locking = locking
        self._file = file
        _cipher = CrCipher(algo.AES(key), 
            supported[mode](*args, **kwargs), defb())
        self._cipher = (_cipher.encryptor()
                        if locking
                        else _cipher.decryptor())

    def authenticate(self, data):
        if not isinstance(data,
            (bytes, memoryview, bytearray)):
            raise TypeError("data must be a bytes object") 
        try:
            self._cipher.authenticate_additional_data(data)
        except bkx.AlreadyUpdated:
            # AEAD ciphers know error
            raise ValueError(
                "cannot authenticate data after update is called") from None

    def update(self, blocksize=16384):
        data = self._file.read(16384)
        if data:
            return self._cipher.update(data)

    def update_into(self, file, tag=None, blocksize=16384):
        if not self._locking and tag is None:
            raise ValueError("Tag is required when decrypring")
        wbuf = memoryview(bytearray(blocksize + 15))
        rbuf = wbuf[:blocksize]
        _write = wbuf[:-15]

        update = self._cipher.update_into
        write = file.write
        reads = iter(partial(self._file.readinto, rbuf), 0)
        for i in reads:
            if i < blocksize:
                rbuf = rbuf[:i]
                wbuf = wbuf[:i+15]
                _write = wbuf[:-15]
            update(rbuf, wbuf)
            write(_write)
        self.finalize(tag)

    def finalize(self, tag=None):
        try:
            if not self._locking:
                if tag is None:
                    raise ValueError("tag is required for decryption")
                self._cipher.finalize_with_tag(tag)
            else:
                self._cipher.finalize()
        except bkx.InvalidTag:
            raise DecryptionError from None
                                         
    def calculate_tag(self):
        if self._locking:
            return self._cipher.tag


@base.cipher
class AESNonAEAD(_utils.HMACMixin, base.Cipher):

    def __init__(self, file, locking, key, mode, *args, **kwargs):
        self._locking = locking
        self._file = file
        self._hasher = hmac.new(key, digestmod='sha256')
        _cipher = CrCipher(algo.AES(key), supported[mode](*args, **kwargs), defb())
        self._cipher = (_cipher.encryptor()
                        if locking
                        else _cipher.decryptor())
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

    def update_into(self, file, tag=None, blocksize=16384):
        if not self._locking and tag is None:
            raise ValueError("Tag is required when decrypring")
        wbuf = memoryview(bytearray(blocksize + 15))
        rbuf = wbuf[:blocksize]

        reads = iter(partial(self._file.readinto,
                    rbuf), 0)
        write = file.write
 

        update = _utils.updater(self._locking,
            self._cipher.update_into,
            self._hasher.update)

        for i in reads:
            if i < blocksize:
                rbuf = rbuf[:i]
            update(rbuf, wbuf)
            write(rbuf)

        self.finalize(tag)

    def finalize(self, tag=None):
        if not self._locking:
            if tag is None:
                raise ValueError("Tag is required for decryption")
            if not hmac.compare_digest(
                self._hasher.digest(), tag):
                raise exc.DecryptionError

