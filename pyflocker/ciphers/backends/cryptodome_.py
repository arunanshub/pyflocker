from functools import partial
import hmac

try:
    from Cryptodome.Cipher import AES
except ModuleNotFoundError:
    from Crypto.Cipher import AES
    import Crypto
    if int(Crypto.__version__[0]) < 3:
        raise

from ..base import Cipher, cipher
from .. import exc
from ._utils import updater, HMACMixin

# all implementations imported here
from .. import AES as m


supported = {
    # classic modes
    m.MODE_CTR : AES.MODE_CTR,
    m.MODE_CFB : AES.MODE_CFB,
    m.MODE_OFB : AES.MODE_OFB,

    # AEAD modes
    m.MODE_GCM : AES.MODE_GCM,
    m.MODE_EAX : AES.MODE_EAX,
    m.MODE_SIV : AES.MODE_SIV,
    m.MODE_CCM : AES.MODE_CCM,
    m.MODE_OCB : AES.MODE_OCB,
}


@cipher
class AESAEAD(Cipher):
    """Cipher wrapper for AEAD supported modes"""

    def __init__(self, file, locking, key, mode, *args, **kwargs):
        self._locking = locking
        self._file = file
        self._cipher = AES.new(key, supported[mode], *args, **kwargs)

    def update(self, blocksize=16384):
        data = self._file.read(blocksize)
        _update = (self._cipher.encrypt
                   if self._locking
                   else self._cipher.decrypt)

        if data:
            return _update(data)

    def update_into(self, file, tag=None, blocksize=16384):
        if not self._locking and tag is None:
            raise ValueError("Tag is required when decrypring")
        buf = memoryview(bytearray(blocksize))
        reads = iter(partial(self._file.readinto, buf), 0)
        write = file.write

        update = (self._cipher.encrypt if self._locking
                  else self._cipher.decrypt)

        for i in reads:
            if i < blocksize:
                buf = buf[:i]
            update(buf, buf)
            write(buf)
        self.finalize(tag)

    def authenticate(self, data):
        if not isinstance(data,
            (bytes, memoryview, bytearray)):
            raise TypeError("data must be a bytes object")
        try:
            self._cipher.update(data)
        except TypeError:
            # AEAD ciphers know error
            raise TypeError("cannot authenticate data after update is called") from None

    def finalize(self, tag=None):
        try:
            if not self._locking:
                if tag is None:
                    raise ValueError("tag is required for decryption")
                self._cipher.verify(tag)
        except ValueError:
            raise exc.DecryptionError from None

    def calculate_tag(self):
        if self._locking:
            return self._cipher.digest()


@cipher
class AESNonAEAD(HMACMixin, Cipher):
    """Cipher wrapper for classic modes of AES"""

    def __init__(self, file, locking, key, mode, *args, **kwargs):
        self._locking = locking
        self._file = file
        self._cipher = AES.new(key, supported[mode], *args, **kwargs)
        self._hasher = hmac.new(key, digestmod='sha256')
        # for authenticate method
        self._updated = False
    
    def update(self, blocksize=16384):
        self._updated = True
        data = self._file.read(blocksize)
        if data:
            if not self._locking:
                self._hasher.update(data)
                return self._cipher.decrypt(data)
            else:
                data = self._cipher.encrypt(data)
                self._hasher.update(data)
                return data

    def update_into(self, file, tag=None, blocksize=16384):
        if not self._locking and tag is None:
            raise ValueError("Tag is required when decrypring")

        # create a buffer for data
        rbuf = memoryview(bytearray(blocksize))

        # get updater methods
        cipherup = (self._cipher.encrypt if self._locking
                  else self._cipher.decrypt)

        # fill buffer with data from source
        reads = iter(partial(self._file.readinto, 
                             rbuf), 0)
        write = file.write

        # updater function (see `_utils.updater`)
        _update = updater(self._locking, cipherup, 
                          self._hasher.update)

        for i in reads:
            if i < blocksize:
                rbuf = rbuf[:i]
            _update(rbuf, rbuf)
            write(rbuf)

        self.finalize(tag)

    def finalize(self, tag=None):
        if not self._locking:
            if tag is None:
                raise ValueError("tag is required for decryption")
            if not hmac.compare_digest(self._hasher.digest(), tag):
                raise exc.DecryptionError


# AES ciphers that needs special attention

class AESAEADOneShot(AESAEAD):
    """Implements AES modes that does not support
    gradual encryption and decryption, which means,
    everything has to be done in one go (one shot)
    """

    def update(self, tag=None, blocksize=16384):
        """Reads data from source and encrypts/decrypts
        it according to the context, and returns bytes
        object.

        Please note that this method can be called only
        once, as the mode won't allow for gradual updates.
        If the decryption fails, then no data is returned,
        and `DecryptionError` is raised instead.
        """

        # dont read here beforehand
        read = self._file.read

        if self._locking:
            # one shot of encrypt
            data = (self._cipher.
                    encrypt_and_digest(
                       read(blocksize))[0])
        else:
            if tag is None:
                raise ValueError(
                    "tag is required for decryption")

            try:
                # one shot of decrypt
                data = (self._cipher.
                        decrypt_and_verify(
                            read(blocksize), tag))
            except ValueError:
                # if error is raised, data won't be
                # returned
                pass

        # finalize here instead (and raise any error
        # that might occur)
        self.finalize(tag)
        return data

    def update_into(self, file, tag=None, blocksize=16384):
        """Reads from the source and writes to the `file`.
        This is equivalent to calling `update(...)` and
        writing the `bytes` data to file.

        Please check the documentation for `update` method.
        """

        # we can update only once, so it is unnecessary
        # to use a separate memory buffer
        file.write(self.update(tag, blocksize))

