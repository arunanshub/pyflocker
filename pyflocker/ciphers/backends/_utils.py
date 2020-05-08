"""Utility tools common to both backend interfaces."""


def updater(locking, cipherup, hashup):
    """Updates a buffer (memoryview), assuming that
    both read and write views share the same internal
    buffer. Used by ciphers which explicitly requires
    HMAC
    """
    if locking:
        def fn(rbuf, wbuf):
            cipherup(rbuf, wbuf)
            # assume that rbuf is filled with data
            # written to wbuf.
            hashup(rbuf)
    else:
        def fn(rbuf, wbuf):
            hashup(rbuf)
            cipherup(rbuf, wbuf)
    return fn


class HMACMixin:
    """Mixin class to add support for HMAC to classic
    ciphers"""

    def authenticate(self, data):
        if self._updated:
            raise TypeError(
                "cannot authenticate data after update is called")
        if not isinstance(data,
            (bytes, memoryview, bytearray)):
            raise TypeError("data must be a bytes object")
 
        self._hasher.update(data)

    def calculate_tag(self):
        if self._locking:
            return self._hasher.digest()

