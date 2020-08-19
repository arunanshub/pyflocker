"""Symmetric cipher wrapper for this backend only."""
from functools import partial

import cryptography.exceptions as bkx
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend as defb

from .._symmetric import CipherWrapperBase, HMACMixin
from .. import base, exc
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

    hash_ = _hashes[hashalgo]()
    hkey = HKDF(
        hash_,
        hash_.digest_size,
        salt,
        b"auth-key",
        defb(),
    ).derive(master_key)
    return key, hkey


class CipherWrapper(CipherWrapperBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not hasattr(self, '_auth'):
            self._auth = None
        locking = self._locking

        self._cipher = (self._cipher.encryptor()
                        if locking else self._cipher.decryptor())
        # for ciphers with HMAC enabled
        self._updated = False
        self._len_ct = 0

    def _get_update(self):
        crpup = self._cipher.update
        hashup = (None if self._auth is None else self._auth.update)

        # AEAD ciphers or HMAC disabled
        if hashup is None:
            return crpup

        if self._locking:

            def update(data):
                self._updated = True
                ctxt = crpup(data)
                self._len_ct += len(ctxt)
                hashup(ctxt)
                return ctxt
        else:

            def update(ctxt):
                self._updated = True
                hashup(ctxt)
                self._len_ct += len(ctxt)
                return crpup(ctxt)

        return update

    def _get_update_into(self):
        crpup = self._cipher.update_into
        hashup = (None if self._auth is None else self._auth.update)

        # AEAD ciphers or HMAC disabled
        if hashup is None:
            return crpup

        if self._locking:

            def update_into(data, out):
                self._updated = True
                crpup(data, out)
                self._len_ct += len(data)
                hashup(out[:-15])
        else:

            def update_into(data, out):
                self._updated = True
                hashup(data)
                self._len_ct += len(data)
                crpup(data, out)

        return update_into


class AEADCipherWrapper(CipherWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._update = self._get_update()
        self._update_into = self._get_update_into()

    def authenticate(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('bytes-like object is required')
        try:
            self._cipher.authenticate_additional_data(data)
        except bkx.AlreadyUpdated as e:
            raise TypeError('cannot authenticate data after '
                            'update has been called') from e

    def finalize(self, tag=None):
        try:
            if not self._locking:
                if tag is None:
                    raise ValueError('tag is required for decryption')
                # finalize: decryption
                return self._cipher.finalize_with_tag(tag)
            # finalize: encryption
            return self._cipher.finalize()

        except bkx.InvalidTag as e:
            raise exc.DecryptionError from e

    def calculate_tag(self):
        if self._locking:
            return self._cipher.tag


class HMACCipherWrapper(HMACMixin, CipherWrapper):
    def __init__(self, *args, **kwargs):
        # we need to do it here since CipherWrapper
        # cannot reach _auth defined in HMACMixin
        super().__init__(*args, **kwargs)
        self._update = self._get_update()
        self._update_into = self._get_update_into()


class FileCipherMixin:
    """ciphers that support r/w to file and file-like
    objects. Mix with cipher wrappers"""

    __slots__ = ('__update', '__update_into', '__file', '__block_size')

    def __init__(self, *args, file, **kwargs):
        self.__file = file
        super().__init__(*args, **kwargs)

        self.__block_size = self._cipher._ctx._block_size_bytes

        self.__update = super()._get_update()
        self.__update_into = super()._get_update_into()

    @base.before_finalized
    def update(self, blocksize=16384):
        """Reads from the source, passes through the
        cipher and returns as `bytes` object.
        Returns None if no more data is available.

        You must finalize by yourself after calling
        this method.

        Args:
            blocksize:
                The amount of data to read from the source.
                The amount is denoted by positive `int`.
                Defaults to 16384 (16 * 1024).

        Returns:
            encrypted or decrypted `bytes` data.
        """
        data = self.__file.read(blocksize)
        if data:
            return self.__update(data)

    @base.before_finalized
    def update_into(self, file, tag=None, blocksize=16384):
        """Writes to `file` and closes the cipher.

        Args:
            tag: The associated tag to validate the decryption.
            blocksize: The size of the chunk of data to read from
                the source in each iteration.

        Returns:
            None

        Raises:
            DecryptionError:
                `tag` is invalid, denoting unsuccessful decryption.
            ValueError:
                the tag is not provided for validation after decryption.
        """
        if not self._locking and tag is None:
            raise ValueError('tag is required for decryption')
        buf = memoryview(bytearray(blocksize + self.__block_size - 1))
        rbuf = buf[:blocksize]

        write = file.write
        reads = iter(partial(self.__file.readinto, rbuf), 0)
        update = self.__update_into

        for i in reads:
            if i < blocksize:
                rbuf = rbuf[:i]
                buf = buf[:i + self.__block_size - 1]
            update(rbuf, buf)
            write(rbuf)
        self.finalize(tag)
