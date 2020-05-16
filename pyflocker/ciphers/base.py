"""Base classes for pyflocker

# Todo
"""

import sys

from functools import wraps
from abc import ABC, abstractmethod

from . import exc


class Cipher(ABC):
    """Base cipher for all other ciphers."""
    
    @abstractmethod
    def update(self, blocksize=16384):
        """Reads from the source, passes through the
        cipher and returns as `bytes` object.
        Returns None if no more data is available.

        You must finalize by yourself after calling
        this method.
        """

    @abstractmethod
    def update_into(self, file, tag=None, blocksize=16384):
        """Writes to `file` and closes the cipher.
        Data is read from the source in blocks specified by `blocksize`. 
        The blocks will have length of at most `blocksize`.

        If `locking` is `False`, then the associated `tag` must
        be supplied, `ValueError` is raised otherwise.

        If the `tag` is invalid, `exc.DecryptionError` is raised
        (see `finalize` method).
        """

    @abstractmethod
    def authenticate(self, data):
        """Authenticates additional data.
        Data must be a bytes, bytearray or memoryview object.
        You can call it to pass additional data that must be
        authenticated, but would be transmitted in the clear.

        If this method is called after calling `update`,
        TypeError is raised.
        """

    @abstractmethod
    def finalize(self, tag=None):
        """Finalizes and closes the cipher.
        
        If `locking` is `False` and the `tag` is not supplied,
        `ValueError` is raised.
        If `locking` is False (ie. Decrypting), and the supplied tag is
        invalid, `exc.DecryptionError` is raised.
        If `locking` is `True`, the cipher is closed. You must calculate
        the associated tag using `calculate_tag` method.
        """
    
    @abstractmethod
    def calculate_tag(self):
        """Calculates and returns the associated `tag`.
        Returns `None` if decrypting.
        This must be called after encryption (ie. `locking` is set to
        `True`).
        """


# ===========================================================
# Decorators and utils for simplifying the creation of cipher wrappers.


def finalizer(f):
    """Finalizes the cipher.
    The wrapped function must be called only once in the
    entire cipher context.
    """
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        if hasattr(self, '_done_'):
            raise exc.AlrealyFinalized("cipher has already been finalized")

        try:
            return f(self, *args, **kwargs)
        finally:
            if sys.exc_info()[0] in (
                exc.DecryptionError, None):
                self._done_ = True

    return wrapper


def before_finalized(f):
    """Methods decorated with this decorator can only be called
    before the cipher has been finalized.

    see: `finalizer`
    """
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        if not hasattr(self, '_done_'):
            return f(self, *args, **kwargs)
        raise exc.AlrealyFinalized(
            "this method can only be called before finalizing")
    return wrapper


def after_finalized(f):
    """Methods decorated with this decorator can only be called
    after the cipher has been finalized.

    see: `finalizer`
    """
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        if hasattr(self, '_done_'):
            return f(self, *args, **kwargs)
        raise exc.NotFinalized(
            "Ciphers must be finalized before calling this method.")
    return wrapper


# ===============================================
# Decorator to ease cipher making


def cipher(cls):
    """Decorator to create a Cipher wrapper.
    It must be applied on a class that derives from
    `Cipher` class.
    """
    if not issubclass(cls, Cipher):
        raise TypeError(
        f"Class must be derived from `{Cipher.__name__}`")

    # decorate methods
    cls.finalize = finalizer(cls.finalize)
    cls.calculate_tag = after_finalized(
        cls.calculate_tag)
    cls.authenticate = before_finalized(cls.authenticate)
    cls.update = before_finalized(cls.update)
    cls.update_into = before_finalized(cls.update_into)

    return cls

