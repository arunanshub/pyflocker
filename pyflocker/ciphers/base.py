"""Base classes for pyflocker

# Todo
"""

import sys

from functools import wraps

from abc import ABC, abstractmethod
from . import exc


class BaseCipher(ABC):
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


class Cipher(BaseCipher):
    """Base class for non-finalized (usable) ciphers."""

    def calculate_tag(self):
        raise exc.NotFinalized("Ciphers must be finalized before calculating tag.")


class ClosedCipher(Cipher):
    """Base class for finalized ciphers."""

    def update(self, *args, **kwargs):
        raise exc.AlrealyFinalized("cannot write to an already finalized cipher.")

    def update_into(self, *args, **kwargs):
        raise exc.AlrealyFinalized("cannot write to an already finalized cipher.")

    def authenticate(self, *args, **kwargs):
        raise exc.AlrealyFinalized("cannot authenticate any more data")

    def finalize(self, *args, **kwargs):
        raise exc.AlrealyFinalized("cipher is already finalized.")


# ===========================================================
# Decorators and utils for simplifying the creation of cipher wrappers.


def _new_state_class(from_cls, to_cls, name,
                     modname=None):
    """Creates new state class with required bases.

    Avoids the bug in __init_subclass__ when using
    types.new_class
    """
    klass = from_cls

    bases = klass.__bases__ + (to_cls, )

    # update class dict
    clsdict = dict(from_cls.__dict__)
    clsdict.update(dict(to_cls.__dict__))
 
    # make the class directly
    new = type(name, bases, clsdict)

    # this module will probably be the source,
    # but can be changed
    new.__module__ = modname or __name__
    return new


def set_state(cls):
    """Decorator to change cipher's state.
    
    Used this decorator to change the state of the cipher.
    It must be applied on the method that is called during finalization.
    It can be called only once.
    """

    def decorator(f):
        @wraps(f)
        def wrapper(self, *args, **kwargs):
            if isinstance(self, cls):
                raise exc.AlrealyFinalized(
                    "this method can be called only once "
                    "during finalization")
            try:
                return f(self, *args, **kwargs)
            finally:
                if sys.exc_info()[0] in (None, exc.DecryptionError):
                    cal = self.calculate_tag

                    # make new state class and replace
                    new = _new_state_class(
                        self.__class__,
                        cls,
                        self.__class__.__name__,
                        self.__module__)
                    self.__class__ = new

                    # If `calculate_tag` is decorated, 
                    # replace with the decorated version.
                    if hasattr(cal, "__wrapped__"):
                        self.calculate_tag = cal
        return wrapper
    return decorator


def finalizer(f):
    """Applied on the method that ends the cipher's context.
    It changes the cipher to `ClosedCipher` instance.
    """
    return set_state(ClosedCipher)(f)


def before_finalized(f):
    """Use this decorator to set the method to be called only if
    the cipher is not finalized yet.

    This is generally required if you are making the cipher manually,
    and need to control it's pre-finalized state's behaviour.
    """
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        if not isinstance(self, ClosedCipher):
            return f(self, *args, **kwargs)
        raise exc.AlrealyFinalized(
            "this method can only be called before finalizing")
    return wrapper


def after_finalized(f):
    """Use this decorator to set the method to be called
    only after `finalize` has been called.
    """
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        if isinstance(self, ClosedCipher):
            return f(self, *args, **kwargs)
        raise exc.NotFinalized(
            "Ciphers must be finalized before calling this method.")
    return wrapper



# ===============================================
# Decorator to ease cipher making


def cipher(cls):
    """Decorator to create a Cipher class.
    It must be applied on a class that derives from
    `OpenedCipher` class.
    """
    if not issubclass(cls, Cipher):
        raise TypeError(
        f"Class must be derived from `{Cipher.__name__}`")

    # check for explicitly defined calculate_tag method
    if Cipher.calculate_tag == cls.calculate_tag:
        raise TypeError("class must explicitly define `calculate_tag` "
                "method to use this decorator")

    # decorate methods
    cls.finalize = finalizer(cls.finalize)
    cls.calculate_tag = after_finalized(
            cls.calculate_tag)
    return cls

