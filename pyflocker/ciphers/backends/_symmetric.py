"""Symmetric cipher wrapper for all backends.
This will be shared by all available backends"""

import hmac
from .. import exc


class CipherWrapperBase:
    def update(self, data):
        return self._update(data)

    def update_into(self, data, out):
        return self._update_into(data, out)


class HMACMixin:
    """Ciphers that can use an HMAC.
    It is NOT necessary for them to support it
    """
    def __init__(self,
                 *args,
                 key,
                 rand,
                 hashed=True,
                 digestmod='sha256',
                 **kwargs):
        if hashed:
            self._hasher = hmac.new(key, digestmod=digestmod)
            self._hasher.update(rand)
        else:
            self._hasher = None
        self._len_aad = 0
        super().__init__(*args, **kwargs)

    def _pad_aad(self):
        if self._len_aad & 0x0F:
            self._hasher.update(bytes(16 - (self._len_aad & 0x0F)))

    def authenticate(self, data):
        # cipher with hmac/hasher disabled
        if self._hasher is None:
            raise NotImplementedError('HMAC is disabled')
        if self._updated:
            raise TypeError('cannot authenticate data after '
                            'update has been called')
        self._hasher.update(data)
        self._len_aad += len(data)

    def finalize(self, tag=None):
        if not self._locking:
            if tag is None:
                raise ValueError('tag is required for decryption')

        try:
            self._cipher.finalize()
        except AttributeError:
            pass

        # cipher with hmac/hasher disabled
        if self._hasher is None:
            return

        if self._len_ct & 0x0F:
            self._hasher.update(bytes(16 - (self._len_ct & 0x0F)))

        if not self._locking:
            if not hmac.compare_digest(self._hasher.digest(), tag):
                raise exc.DecryptionError

    def calculate_tag(self):
        # cipher with no hmac/hasher
        if self._hasher is None:
            raise NotImplementedError('HMAC is disabled')
        if self._locking:
            return self._hasher.digest()
