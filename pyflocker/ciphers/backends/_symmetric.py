"""Symmetric cipher wrapper for all backends.
This will be shared by all available backends"""

import hmac
from .. import exc


class CipherWrapperBase:
    """Represents the general functionality of ciphers
    performing generic functionality."""
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
                 key=None,
                 rand=None,
                 hashed=True,
                 digestmod='sha256',
                 **kwargs):
        super().__init__(*args, **kwargs)
        if hashed:
            self._auth = hmac.new(key, digestmod=digestmod)
            self._auth.update(rand)
        else:
            self._auth = None
        self._len_aad = 0

    def _pad_aad(self):
        """Pads the Additional authenticated data.
        Must be called only once before calling `update` or
        `update_into`."""
        if self._len_aad & 0x0F:
            self._auth.update(bytes(16 - (self._len_aad & 0x0F)))

    def authenticate(self, data):
        # cipher with hmac/hasher disabled
        if self._auth is None:
            raise NotImplementedError('HMAC is disabled')
        if self._updated:
            raise TypeError('cannot authenticate data after '
                            'update has been called')
        self._auth.update(data)
        self._len_aad += len(data)

    def finalize(self, tag=None):
        if not self._locking:
            if tag is None:
                raise ValueError('tag is required for decryption')

        try:
            # pyca/cryptography ciphers needs to be finalized
            self._cipher.finalize()
        except AttributeError:
            pass

        # cipher with hmac/hasher disabled
        if self._auth is None:
            return

        # pad the ciphertext to hasher
        if self._len_ct & 0x0F:
            self._auth.update(bytes(16 - (self._len_ct & 0x0F)))

        if not self._locking:
            if not hmac.compare_digest(self._auth.digest(), tag):
                raise exc.DecryptionError

    def calculate_tag(self):
        # cipher with no hmac/hasher
        if self._auth is None:
            raise NotImplementedError('HMAC is disabled')
        if self._locking:
            return self._auth.digest()
