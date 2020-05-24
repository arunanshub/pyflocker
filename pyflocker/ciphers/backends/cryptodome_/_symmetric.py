"Symmetric cipher wrapper for this backend only."""


from .._symmetric import CipherWrapperBase, HMACMixin
from .._utils import updater
from .. import base

from functools import partial
from .._utils import updater


class CipherWrapper(CipherWrapperBase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # no hasher defined
        if not hasattr(self, '_hasher'):
            self._hasher = None

        locking = self._locking
        _crpup = (self._cipher.encrypt if locking
                  else self._cipher.decrypt)
        _hashup = (None if self._hasher is None
                   else self._hasher.update)
 
        # for generic ciphers only
        self._update = updater(locking, _crpup,
            _hashup, buffered=False)
        self._update_into = updater(locking, _crpup,
            _hashup, shared=False)
 
        # for non-aead ciphers only
        self._updated = False


class AEADCipherWrapper(CipherWrapper):

    def authenticate(self, data):
        if not isinstance(data,
                (bytes, bytearray, memoryview)):
            raise TypeError('data type incorrect')
        try:
            self._cipher.update(data)
        except TypeError:
            raise TypeError(
                'cannot authenticate') from None

    def finalize(self, tag=None):
        try:
            if not self._locking:
                if tag is None:
                    raise ValueError('tag required')
                self._cipher.verify(tag)
        except ValueError:
            raise exc.DecryptionError from None

    def calculate_tag(self):
        if self._locking:
            return self._cipher.digest()


class HMACCipherWrapper(HMACMixin, CipherWrapper):
    pass

class FileCipherMixin:
    """ciphers that support r/w to file and file-like
    objects. Mix with cipher wrappers"""

    __slots__ = ()

    def __init__(self, *args, file, **kwargs):
        self.__file = file
        # must use hasher
        kwargs.pop('hashed', None)

        super().__init__(*args, **kwargs)

        _crpup = (self._cipher.encrypt
                  if self._locking
                  else self._cipher.decrypt)

        if self._hasher is not None:
            _hashup = self._hasher.update
        else:
            _hashup = None

        self.__update = updater(self._locking,
            _crpup, _hashup, buffered=False)
        self.__update_into = updater(self._locking,
            _crpup, _hashup)
    
    @base.before_finalized
    def update(self, blocksize=16384):
        self._updated = True
        data = self.__file.read(blocksize)
        if data:
            return self.__update(data)

    @base.before_finalized
    def update_into(self, file, tag=None, blocksize=16384):
        if not self._locking and tag is None:
            raise ValueError('tag required')
        buf = memoryview(bytearray(blocksize))

        write = file.write
        reads = iter(partial(
            self.__file.readinto, buf), 0)
        update = self.__update_into

        for i in reads:
            if i < blocksize:
                buf = buf[:i]
            update(buf, buf)
            write(buf)
        self.finalize(tag)

