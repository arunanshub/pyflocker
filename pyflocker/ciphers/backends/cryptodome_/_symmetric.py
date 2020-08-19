"Symmetric cipher wrapper for this backend only." ""
from functools import partial
try:
    from Cryptodome.Protocol import KDF
except ModuleNotFoundError:
    from Crypto.Protocol import KDF

from ._hashes import hashes as _hashes
from .._symmetric import CipherWrapperBase, HMACMixin
from .. import base, exc


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

    hash_ = _hashes[hashalgo]()
    hkey = KDF.HKDF(
        master=master_key,
        key_len=hash_.digest_size,
        salt=salt,
        hashmod=hash_,
        num_keys=1,
        context=b"auth-key",
    )
    return key, hkey


class CipherWrapper(CipherWrapperBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # no hasher defined
        if not hasattr(self, '_auth'):
            self._auth = None

        # for non-aead ciphers only
        self._updated = False
        self._len_ct = 0  # will be needed by HMACMixin

    def _get_update(self):
        crpup = (self._cipher.encrypt
                 if self._locking else self._cipher.decrypt)
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
        crpup = (self._cipher.encrypt
                 if self._locking else self._cipher.decrypt)
        hashup = (None if self._auth is None else self._auth.update)

        # AEAD ciphers or HMAC disabled
        if hashup is None:
            return crpup

        if self._locking:

            def update_into(data, out):
                self._updated = True
                crpup(data, out)
                self._len_ct += len(out)
                hashup(out)
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
            self._cipher.update(data)
        except TypeError as e:
            raise TypeError('cannot authenticate data after '
                            'update has been called') from e

    def finalize(self, tag=None):
        try:
            if not self._locking:
                if tag is None:
                    raise ValueError('tag is required for decryption')
                self._cipher.verify(tag)
        except ValueError as e:
            raise exc.DecryptionError from e

    def calculate_tag(self):
        if self._locking:
            return self._cipher.digest()


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

    __slots__ = ('__file', '__update', '__update_into')

    def __init__(self, *args, file, **kwargs):
        self.__file = file

        super().__init__(*args, **kwargs)

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
            TypeError:
                the tag is not provided for validation after decryption.
        """
        if not self._locking and tag is None:
            raise ValueError('tag is required for decryption')
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
