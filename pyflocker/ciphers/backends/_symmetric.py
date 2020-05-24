"""Symmetric cipher wrapper for all backends.
This will be shared by all available backends"""


import hmac


class CipherWrapperBase:

    def update(self, data):
        # for non-aead only; has no effect on aead
        self._updated = True
        return self._update(data)

    def update_into(self, data, out):
        return self._update_into(data, out)


class HMACMixin:
    """Ciphers that need hmac.
    It is NOT necessary for them to support it
    """
    def __init__(self, *args, key, hashed=True,
        digestmod='sha256', **kwargs):
        if hashed:
            self._hasher = hmac.new(key,
                digestmod=digestmod)
        else:
            self._hasher = None
        super().__init__(*args, **kwargs)

    def authenticate(self, data):
        # cipher with hmac/hasher disabled
        if self._hasher is None:
            raise NotImplementedError('HMAC is disabled')
        if self._updated:
            raise TypeError(
                'cannot authenticate data after '
                'update has been called')
        self._hasher.update(data)

    def finalize(self, tag=None):
        # cipher with hmac/hasher disabled
        if self._hasher is None:
            return

        if not self._locking:
            if tag is None:
                raise ValueError(
                    'tag is required for decryption')
            if not hmac.compare_digest(
                self._hasher.digest(), tag):
                raise DecryptionError

    def calculate_tag(self):
        # cipher with no hmac/hasher
        if self._hasher is None:
            raise NotImplementedError('HMAC is disabled')
        if self._locking:
            return self._hasher.digest()



