"""Tools for Symmetric ciphers common to all the backends."""

import hmac
import typing
from functools import partial

from .. import base, exc


class FileCipherWrapper(base.BaseAEADCipher):
    """
    Wraps ciphers that support BaseAEADCipher interface and provides
    file encryption and decryption facility.
    """

    def __init__(
        self,
        cipher: base.BaseAEADCipher,
        file: typing.BinaryIO,
        offset: int = 0,
    ):
        """Initialize a file cipher wrapper.

        Args:
            cipher (:any:`base.BaseAEADCipher`):
                A cipher that supports :py:class:`BaseAEADCipher` interface.
            file (filelike):
                A file or file-like object.
            offset (int):
                The difference between the length of ``in`` buffer and
                ``out`` buffer in ``update_into`` method of a BaseAEADCipher.
        """
        if not isinstance(cipher, base.BaseAEADCipher):
            raise TypeError("cipher must implement BaseAEADCipher interface.")

        # the cipher already has an internal context
        self._ctx = cipher
        self._file = file
        self._tag = None
        self._encrypting = self._ctx.is_encrypting()
        self._offset = offset

    def authenticate(self, data):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        return self._ctx.authenticate(data)

    def is_encrypting(self):
        return self._encrypting

    def update(self, blocksize: int = 16384) -> bytes:
        """
        Reads at most ``blocksize`` bytes from ``file``, passes through the
        cipher and returns the cipher's output.

        Args:
            blocksize (int): Maximum amount of data to read in a single call.

        Returns:
            bytes: Encrypted or decrypted data.

        Raises:
            AlreadyFinalized: if the cipher has been finalized.
        """
        if self._ctx is None:
            raise exc.AlreadyFinalized
        if (data := self._file.read(blocksize)) :
            return self._ctx.update(data)

    def update_into(
        self,
        file: typing.BinaryIO,
        tag: typing.Optional[typing.ByteString] = None,
        blocksize: int = 16384,
    ) -> None:
        """
        Read from ``infile``, pass through cipher and write the output of the
        cipher to ``file``. Use this method if you want to encrypt/decrypt the
        ``infile`` and write its output to ``outfile``.

        This method is very fast
        (compared to :py:meth:`FileCipherWrapper.update`) because no
        intermediate copies of data are made during the entire operation.

        Args:
            file (filelike): File to write the output of the cipher into.
            tag (bytes-like, None):
                The tag to verify decryption. If the file is being decrypted,
                this must be passed.
            blocksize (int): Maximum amount of data to read in a single call.

        Raises:
            AlreadyFinalized: if the cipher has been finalized.
            ValueError: if the file is being decrypted and tag is not supplied.
        """
        if self._ctx is None:
            raise exc.AlreadyFinalized
        if not self._encrypting:
            if tag is None:
                raise ValueError("tag is required for decryption")

        buf = memoryview(bytearray(blocksize + self._offset))
        rbuf = buf[:blocksize]

        # localize variables for better performance
        offset = self._offset
        write = file.write
        reads = iter(partial(self._file.readinto, rbuf), 0)
        update = self._ctx.update_into

        for i in reads:
            if i < blocksize:
                rbuf = rbuf[:i]
                buf = buf[: i + offset]
            update(rbuf, buf)
            write(rbuf)

        self.finalize(tag)

    def finalize(self, tag=None):
        if self._ctx is None:
            raise exc.AlreadyFinalized

        try:
            self._ctx.finalize(tag)
        finally:
            self._tag, self._ctx = self._ctx.calculate_tag(), None

    def calculate_tag(self):
        if self._ctx is not None:
            raise exc.NotFinalized("Cipher has already been finalized.")
        return self._tag


StreamCipherWrapper = FileCipherWrapper


class HMACWrapper(base.BaseAEADCipher):
    """
    Wraps a cipher that supports BaseNonAEADCipher cipher interface and
    provides authentication capability using HMAC.
    """

    def __init__(
        self,
        cipher: base.BaseNonAEADCipher,
        hkey: typing.ByteString,
        rand: typing.ByteString,
        digestmod: typing.Union[str, base.BaseHash] = "sha256",
        offset: int = 0,
    ):
        if not isinstance(cipher, base.BaseNonAEADCipher):
            raise TypeError("Only NonAEAD ciphers can be wrapped.")

        if isinstance(digestmod, base.BaseHash):
            # always use a fresh hash object.
            digestmod = digestmod.new()
        self._auth = hmac.new(hkey, digestmod=digestmod)

        self._auth.update(rand)
        self._ctx = self._get_mac_ctx(cipher, self._auth, offset)

        self._encrypting = cipher.is_encrypting()
        self._len_aad, self._len_ct = 0, 0
        self._updated = False

    def is_encrypting(self):
        return self._encrypting

    def authenticate(self, data):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        if self._updated:
            raise TypeError(
                "Cannot call authenticate after update/update_into has been"
                " called"
            )
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
        self._len_ct += len(data)
        self._ctx.update_into(data, out)

    def finalize(self, tag=None):
        if self._ctx is None:
            raise exc.AlreadyFinalized

        if not self.is_encrypting():
            if tag is None:
                raise ValueError("tag is required for decryption")

        self._auth.update(self._len_aad.to_bytes(8, "little"))
        self._auth.update(self._len_ct.to_bytes(8, "little"))

        self._ctx = None

        if not self._encrypting:
            if not hmac.compare_digest(self._auth.digest(), tag):
                raise exc.DecryptionError

    def calculate_tag(self):
        if self._ctx is not None:
            raise exc.NotFinalized

        if self.is_encrypting():
            return self._auth.digest()

    @staticmethod
    def _get_mac_ctx(cipher: base.BaseNonAEADCipher, auth, offset):
        if cipher.is_encrypting():
            return _EncryptionCtx(cipher, auth, offset)
        return _DecryptionCtx(cipher, auth)


class _EncryptionCtx:
    def __init__(self, cipher: base.BaseNonAEADCipher, auth, offset):
        self._ctx = cipher
        self._auth = auth
        self._offset = -offset or None

    def update(self, data):
        ctxt = self._ctx.update(data)
        self._auth.update(ctxt)
        return ctxt

    def update_into(self, data, out):
        self._ctx.update_into(data, out)
        self._auth.update(out[: self._offset])


class _DecryptionCtx:
    def __init__(self, cipher: base.BaseNonAEADCipher, auth):
        self._ctx = cipher
        self._auth = auth

    def update(self, data):
        self._auth.update(data)
        return self._ctx.update(data)

    def update_into(self, data, out):
        self._auth.update(data)
        self._ctx.update_into(data, out)
