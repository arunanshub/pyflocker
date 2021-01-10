from functools import partial

from ... import base, exc


class NonAEADCipherTemplate(base.BaseNonAEADCipher):
    """
    Template class to provide the default behavior if BaseNonAEADCipher.

    Subclasses need to provide:
        - `_encrypting`
        - `_update_func`
    """

    def is_encrypting(self):
        return self._encrypting

    def update(self, data):
        if self._update_func is None:
            raise exc.AlreadyFinalized
        return self._update_func(data)

    def update_into(self, data, out):
        if self._update_func is None:
            raise exc.AlreadyFinalized
        self._update_func(data, out)

    def finalize(self):
        if not self._update_func:
            raise exc.AlreadyFinalized

        self._update_func = None


class AEADCipherTemplate(base.BaseAEADCipher):
    """
    Template class to provide the default behavior if BaseAEADCipher.

    Subclasses need to provide the following attributes:
        - `_encrypting`
        - `_update_func`
        - `_cipher`
        - `_updated`
    """

    def is_encrypting(self):
        return self._encrypting

    def update(self, data):
        self._updated = True
        if self._update_func is None:
            raise exc.AlreadyFinalized
        return self._update_func(data)

    def update_into(self, data, out):
        self._updated = True
        if self._update_func is None:
            raise exc.AlreadyFinalized
        self._update_func(data, out)

    def authenticate(self, data):
        if self._update_func is None:
            raise exc.AlreadyFinalized
        if self._updated:
            raise TypeError
        self._cipher.update(data)

    def finalize(self, tag=None):
        if self._update_func is None:
            raise exc.AlreadyFinalized

        if not self._encrypting and tag is None:
            raise ValueError("tag is required for finalization")

        self._update_func = None

        try:
            if not self._encrypting:
                self._cipher.verify(tag)
        except ValueError as e:
            raise exc.DecryptionError from e

    def calculate_tag(self):
        if self._update_func is not None:
            raise exc.NotFinalized

        return self._cipher.digest()


class FileCipherWrapper(base.BaseAEADCipher):
    def __init__(self, cipher: base.BaseAEADCipher, file):
        self._cipher = cipher
        self.__file = file
        self.__tag = None
        self.__encrypting = self._cipher.is_encrypting()

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

        buf = memoryview(bytearray(blocksize))

        write = file.write
        reads = iter(partial(self.__file.readinto, buf), 0)
        update = self._cipher.update_into

        for i in reads:
            if i < blocksize:
                buf = buf[:i]
            update(buf, buf)
            write(buf)

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
