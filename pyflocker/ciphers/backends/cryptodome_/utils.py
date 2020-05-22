from functools import partial
from .._utils import updater


class FileCipherMixin:

    __slots__ = ()

    def __init__(self, *args, file, **kwargs):
        self.__file = file
        kwargs.pop('hashed', None)

        super().__init__(*args, **kwargs)

        _crpup = (self._cipher.encrypt
                  if self._locking
                  else self._cipher.decrypt)

        if hasattr(self, '_hasher'):
            _hashup = self._hasher.update
        else:
            _hashup = None

        self.__update = updater(
            self._locking,
            _crpup, _hashup, buffered=False)

        self.__update_into = updater(
            self._locking,
            _crpup, _hashup)

    def update(self, blocksize=16384):
        self._updated = True
        data = self.__file.read(blocksize)
        if data:
            return self.__update(data)

    def update_into(self, file, tag=None, blocksize=16384):
        if not self._locking and tag is None:
            raise ValueError('tag required')
        buf = memoryview(bytearray(blocksize))

        write = file.write
        reads = iter(partial(self.__file.readinto, buf), 0)
        update = self.__update_into

        for i in reads:
            if i < blocksize:
                buf = buf[:i]
            update(buf, buf)
            write(buf)
        self.finalize(tag)

