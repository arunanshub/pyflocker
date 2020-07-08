"Symmetric cipher wrapper for this backend only." ""
try:
    from Cryptodome.Protocol import KDF
except ModuleNotFoundError:
    from Crypto.Protocol import KDF

from ._hashes import hashes as _hashes
from .._symmetric import CipherWrapperBase, HMACMixin
from .._utils import updater
from .. import base, exc

from functools import partial
from .._utils import updater


def derive_key(master_key, dklen, hashalgo, salt):
    """Derive key materials for HMAC from given master key."""
    key = KDF.HKDF(
        master=master_key,
        key_len=dklen,
        salt=salt,
        hashmod=_hashes[hashalgo](),
        num_keys=1,
        context=b"enc-key",
    )

    hkey = KDF.HKDF(
        master=master_key,
        key_len=32,
        salt=salt,
        hashmod=_hashes[hashalgo](),
        num_keys=1,
        context=b"auth-key",
    )
    return key, hkey


class CipherWrapper(CipherWrapperBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # no hasher defined
        if not hasattr(self, '_hasher'):
            self._hasher = None

        locking = self._locking
        _crpup = (self._cipher.encrypt if locking else self._cipher.decrypt)
        _hashup = (None if self._hasher is None else self._hasher.update)

        # for generic ciphers only
        self._update = updater(locking, _crpup, _hashup, buffered=False)
        self._update_into = updater(locking, _crpup, _hashup, shared=False)

        # for non-aead ciphers only
        self._updated = False


class AEADCipherWrapper(CipherWrapper):
    def authenticate(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('bytes-like object is required')
        try:
            self._cipher.update(data)
        except TypeError:
            raise TypeError('cannot authenticate data after '
                            'update has been called') from None

    def finalize(self, tag=None):
        try:
            if not self._locking:
                if tag is None:
                    raise TypeError('tag is required for decryption')
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
                  if self._locking else self._cipher.decrypt)

        if self._hasher is not None:
            _hashup = self._hasher.update
        else:
            _hashup = None

        self.__update = updater(self._locking, _crpup, _hashup, buffered=False)
        self.__update_into = updater(self._locking, _crpup, _hashup)

    @base.before_finalized
    def update(self, blocksize=16384):
        """Reads from the source, passes through the
        cipher and returns as `bytes` object.
        Returns None if no more data is available.

        You must finalize by yourself after calling
        this method.
        """
        self._updated = True
        data = self.__file.read(blocksize)
        if data:
            return self.__update(data)

    @base.before_finalized
    def update_into(self, file, tag=None, blocksize=16384):
        """Writes to `file` and closes the cipher.
        Data is read from the source in blocks specified by `blocksize`. 
        The blocks will have length of at most `blocksize`.

        If `locking` is `False`, then the associated `tag` must
        be supplied, `ValueError` is raised otherwise.

        If the `tag` is invalid, `exc.DecryptionError` is raised
        (see `finalize` method).
        """
        if not self._locking and tag is None:
            raise TypeError('tag is required for decryption')
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
