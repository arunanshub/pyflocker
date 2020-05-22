from functools import partial
import hmac

try:
    from Cryptodome.Cipher import AES
except ModuleNotFoundError:
    from Crypto.Cipher import AES

from .. import exc, base, Modes as _m
from .. import _utils
from .utils import FileCipherMixin


supported = {
    # classic modes
    _m.MODE_CTR : AES.MODE_CTR,
    _m.MODE_CFB : AES.MODE_CFB,
    _m.MODE_OFB : AES.MODE_OFB,

    # AEAD modes
    _m.MODE_GCM : AES.MODE_GCM,
    _m.MODE_EAX : AES.MODE_EAX,
    _m.MODE_SIV : AES.MODE_SIV,
    _m.MODE_CCM : AES.MODE_CCM,
    _m.MODE_OCB : AES.MODE_OCB,
}


@base.cipher
class AEAD(base.Cipher):
    """Cipher wrapper for AEAD supported modes"""

    def __init__(self, locking, key, mode,
                 *args, **kwargs):

        self._locking = locking
        self._cipher = AES.new(key,
            supported[mode], *args, **kwargs)

        self._update = (self._cipher.encrypt
                        if locking
                        else self._cipher.decrypt)

    def update(self, data):
        return self._update(data)

    def update_into(self, data, out):
        return self._update(data, out)

    def authenticate(self, data):
        if not isinstance(data,
            (bytes, memoryview, bytearray)):
            raise TypeError(
                "data must be a bytes object")
        try:
            self._cipher.update(data)
        except TypeError:
            # AEAD ciphers know error
            raise TypeError(
                "cannot authenticate data after "
                "update is called") from None

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


class AEADFile(FileCipherMixin, AEAD):
    pass


@base.cipher
class NonAEAD(_utils.HMACMixin, base.Cipher):
    """Cipher wrapper for classic modes of AES"""

    def __init__(self, locking, key, mode,
                 *args, **kwargs):

        self._locking = locking

        if kwargs.pop('hashed', True):
            self._hasher = hmac.new(key,
                digestmod=kwargs.pop(
                    'digestmod', 'sha256'))
            _hashup = self._hasher.update
        else:
            self._hasher = None
            _hashup = None

        self._cipher = AES.new(key,
            supported[mode], *args, **kwargs)
        
        _crpup = (self._cipher.encrypt
                  if locking
                  else self._cipher.decrypt)
        
        # used as generic cipher
        self._update = _utils.updater(
            locking, _crpup, _hashup,
            buffered=False)
        
        self._update_into = _utils.updater(
            locking, _crpup, _hashup,
            shared=False)

        # for authenticate method
        self._updated = False
    
    def update(self, data):
        self._updated = True
        return self._update(data)

    def update_into(self, data, out):
        return self._update_into(data, out)

    def finalize(self, tag=None):
        if self._hasher is None:
            return
        if not self._locking:
            if tag is None:
                raise ValueError("tag is required for decryption")
            if not hmac.compare_digest(
                self._hasher.digest(), tag):
                raise exc.DecryptionError


class NonAEADFile(FileCipherMixin, NonAEAD):
    pass


# AES ciphers that needs special attention

class AEADOneShot(AEAD):
    """Implements AES modes that does not support
    gradual encryption and decryption, which means,
    everything has to be done in one go (one shot)
    """

    def update(self, data, out=None, tag=None):
        if self._locking:
            return self._cipher.encrypt_and_digest(
                data, out)[0]
            self.finalize()
        else:
            if tag is None:
                raise ValueError('tag required')
            crpup = self._cipher.decrypt_and_verify
        try:
            return crpup(data, tag, out)
        except ValueError:
            pass
        self.finalize(tag)

    def update_into(self, data, out, tag=None):
        self.update(data, out, tag)

