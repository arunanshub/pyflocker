"Symmetric cipher wrapper for this backend only." ""

import cryptography.exceptions as bkx
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend as defb
from .._symmetric import (CipherWrapperBase, HMACMixin)
from .._utils import updater
from .. import base, exc

from functools import partial
from .._utils import updater
from ._hashes import hashes as _hashes


def derive_key(master_key, dklen, hashalgo, salt):
    """Derive key materials for HMAC from given master key."""
    key = HKDF(
        _hashes[hashalgo](),
        dklen,
        salt,
        b"enc-key",
        defb(),
    ).derive(master_key)

    hkey = HKDF(
        _hashes[hashalgo](),
        32,
        salt,
        b"auth-key",
        defb(),
    ).derive(master_key)
    return key, hkey


class CipherWrapper(CipherWrapperBase):
    def __init__(self, *args, **kwargs):
        if not hasattr(self, '_hasher'):
            self._hasher = None

        _hashup = (None if self._hasher is None else self._hasher.update)

        locking = self._locking
        self._cipher = _crp = (self._cipher.encryptor()
                               if locking else self._cipher.decryptor())
        # for generic ciphers only
        self._update = updater(locking, _crp.update, _hashup, buffered=False)
        self._update_into = updater(locking,
                                    _crp.update_into,
                                    _hashup,
                                    shared=False)

        # for non-aead ciphers only
        self._updated = False
        super().__init__(*args, **kwargs)


class AEADCipherWrapper(CipherWrapper):
    def authenticate(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('bytes-like object is required')
        try:
            (self._cipher.authenticate_additional_data(data))
        except bkx.AlreadyUpadated:
            raise TypeError('cannot authenticate data after '
                            'update has been called') from None

    def finalize(self, tag=None):
        try:
            if not self._locking:
                if tag is None:
                    raise TypeError('tag is required for decryption')
                return self._cipher.finalize_with_tag(tag)
            return self._cipher.finalize()
        except bkx.InvalidTag:
            raise exc.DecryptionError from None

    def calculate_tag(self):
        if self._locking:
            return self._cipher.tag


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
        if self._hasher is not None:
            _hashup = self._hasher.update
        else:
            _hashup = None

        self.__update = updater(self._locking,
                                self._cipher.update,
                                _hashup,
                                buffered=False)

        self.__update_into = updater(self._locking, self._cipher.update_into,
                                     _hashup)

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
            raise ValueError('tag is required for decryption')
        buf = memoryview(bytearray(blocksize + 15))
        rbuf = buf[:blocksize]

        write = file.write
        reads = iter(partial(self.__file.readinto, buf), 0)
        update = self.__update_into

        for i in reads:
            if i < blocksize:
                rbuf = rbuf[:i]
            update(rbuf, buf)
            write(rbuf)
        self.finalize(tag)
