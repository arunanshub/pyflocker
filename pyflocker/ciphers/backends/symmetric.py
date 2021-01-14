import hmac
from functools import partial

from .. import base, exc


class FileCipherWrapper(base.BaseAEADCipher):
    def __init__(self, cipher: base.BaseAEADCipher, file, offset=0):
        self._cipher = cipher
        self.__file = file
        self.__tag = None
        self.__encrypting = self._cipher.is_encrypting()
        self.__offset = offset

    def authenticate(self, data):
        if self._cipher is None:
            raise exc.AlreadyFinalized
        return self._cipher.authenticate(data)

    def is_encrypting(self):
        return self.__encrypting

    def update(self, blocksize=16384):
        if self._cipher is None:
            raise exc.AlreadyFinalized
        if (data := self.__file.read(blocksize)) :
            return self._cipher.update(data)

    def update_into(self, file, tag=None, blocksize=16384):
        if self._cipher is None:
            raise exc.AlreadyFinalized
        if not self._cipher.is_encrypting():
            raise ValueError("tag is required")

        buf = memoryview(bytearray(blocksize + self.__offset))
        rbuf = buf[:blocksize]

        write = file.write
        reads = iter(partial(self.__file.readinto, buf), 0)
        update = self._cipher.update_into

        for i in reads:
            if i < blocksize:
                rbuf = rbuf[:i]
                buf = buf[: i + self.__offset]
            update(rbuf, buf)
            write(rbuf)

        self.finalize(tag)

    def finalize(self, tag=None):
        if self._cipher is None:
            raise exc.AlreadyFinalized

        try:
            self._cipher.finalize(tag)
        finally:
            self.__tag, self._cipher = self._cipher.calculate_tag(), None

    def calculate_tag(self):
        if self._cipher is not None:
            raise exc.NotFinalized
        return self.__tag


class HMACWrapper(base.BaseAEADCipher):
    def __init__(
        self,
        cipher: base.BaseNonAEADCipher,
        hkey: bytes,
        rand: bytes,
        digestmod: str = "sha256",
        offset: int = 0,
    ):
        if not isinstance(cipher, base.BaseNonAEADCipher):
            raise TypeError("Only NonAEAD ciphers can be wrapped.")

        self._cipher = cipher
        self._auth = hmac.new(hkey, digestmod=digestmod)
        self._offset = offset

        self._auth.update(rand)
        self._ctx = self._get_mac_ctx(cipher, self._auth, offset)

        self._len_aad, self._len_ct = 0, 0
        self._updated = False

    def is_encrypting(self):
        return self._cipher.is_encrypting()

    def authenticate(self, data):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        if self._updated:
            raise TypeError
        self._auth.update(data)
        self._len_aad += len(data)

    def update(self, data):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._updated = True
        self._len_ct += len(data)
        return self._ctx.update(data)

    def update_into(self, data, out):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._updated = True
        self._len_ct += len(out[: -self._offset])
        self._ctx.update_into(data, out)

    def finalize(self, tag=None):
        if self._ctx is None:
            raise exc.AlreadyFinalized

        if not self._cipher.is_encrypting():
            if tag is None:
                raise ValueError("tag is required for decryption")

        self._auth.update(self._len_aad.to_bytes(8, "little"))
        self._auth.update(self._len_ct.to_bytes(8, "little"))

        self._ctx = None

        if not self._cipher.is_encrypting():
            if not hmac.compare_digest(self._auth.digest(), tag):
                raise exc.DecryptionError

    def calculate_tag(self):
        if self._ctx is not None:
            raise exc.NotFinalized

        if self._cipher.is_encrypting():
            return self._auth.digest()

    @staticmethod
    def _get_mac_ctx(cipher: base.BaseNonAEADCipher, auth, offset):
        if cipher.is_encrypting():
            return _EncryptionCtx(cipher, auth, offset)
        return _DecryptionCtx(cipher, auth)


class _EncryptionCtx:
    def __init__(self, cipher: base.BaseNonAEADCipher, auth, offset):
        self._cipher = cipher
        self._auth = auth
        self._offset = offset

    def update(self, data):
        ctxt = self._cipher.update(data)
        self._auth.update(ctxt)
        return ctxt

    def update_into(self, data, out):
        self._cipher.update_into(data, out)
        self._auth.update(out[: -self._offset])


class _DecryptionCtx:
    def __init__(self, cipher: base.BaseNonAEADCipher, auth):
        self._cipher = cipher
        self._auth = auth

    def update(self, data):
        self._auth.update(data)
        return self._cipher.update(data)

    def update_into(self, data, out):
        self._auth.update(data)
        self._cipher.update_into(data, out)
