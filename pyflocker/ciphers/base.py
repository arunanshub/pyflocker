"""Base classes for pyflocker."""

import sys

from functools import wraps, partial
from abc import ABC, abstractmethod

from . import exc


class Cipher(ABC):
    """Base cipher for all other ciphers."""
    @abstractmethod
    def update(self, data):
        """Takes bytes-like object and returns
        encrypted/decrypted bytes object.

        Args:
            data: The bytes-like object to pass to the cipher.

        Returns:
            bytes-like encrypted data.
        """

    @abstractmethod
    def update_into(self, data, out):
        """Works almost like `update` method, except
        for it fills a preallocated buffer with data
        with no intermideate copying of data.

        Args:
            data:
                The bytes-like object to pass to the cipher.
            out:
                The buffer interface where the encrypted/decrypted
                data must be written into.

        Returns:
            None
        """

    @abstractmethod
    def authenticate(self, data):
        """Authenticates additional data.
        Data must be a bytes, bytearray or memoryview object.
        You can call it to pass additional data that must be
        authenticated, but would be transmitted in the clear.

        Args:
            data: The bytes-like object that must be authenticated.

        Returns:
            None

        Raises:
            TypeError is raised if this method is called after calling
            `update`.
        """

    @abstractmethod
    def finalize(self, tag=None):
        """Finalizes and closes the cipher.

        Args:
            tag:
                The associated tag that authenticates the decryption.
                `tag` is required for decryption only. If the mode is
                not AEAD, tag is not required for verification.

        Returns:
            None

        Raises:
            ValueError: If cipher is decrypting and tag is not supplied.
            DecryptionError: If the decryption was incorrect.
        """

    @abstractmethod
    def calculate_tag(self):
        """Calculates and returns the associated `tag`.
        Args:
            None

        Returns:
            `None` if decrypting.
            bytes-like tag if encrypting.

        Raises:
            NotImplementedError if the mode is non-AEAD or cipher doesn't
            support AEAD.
        """


class BaseHash(ABC):
    @property
    @abstractmethod
    def digest_size(self):
        """The digest size of the hash algorithm."""

    @property
    @abstractmethod
    def name(self):
        """Name of the hash algorithm."""

    @abstractmethod
    def update(self, data):
        """Update the hash function

        Args:
            data: The bytes-like object to pass to the hash algorithm.

        Returns:
            None
        """

    @abstractmethod
    def copy(self):
        """Return a copy of the hash function.
        This cannot be called after digest has been called.

        Args:
            None

        Returns:
            Hash object.
        """

    @abstractmethod
    def digest(self):
        """Finalize and return the hash as bytes object.

        Args:
            None

        Returns:
            bytes object representing the digest of the message.
        """

    @abstractmethod
    def new(self, data=b'', *, digest_size=None):
        """Return a new hash object.

        Args:
            data: The initial data to be passed to the hash object.

        Kwargs:
            digest_size:
                The digest size of the hash algorithm.
                If digest_size is None, it is equal to the current
                hash object's digest size.
                Valid only for BLAKE and SHAKE.

        Returns:
            Hash object.

        Raises:
            See documentation for Hash.
        """

    def __repr__(self):
        return f"<Hash '{self.name}' at {hex(id(self))}>"


class BaseAsymmetricKey(ABC):
    """Represents the base key interface."""
    @abstractmethod
    def serialize(self):
        """Serialize the key into a storable format."""

    @classmethod
    @abstractmethod
    def load(cls, data, passphrase=None):
        """Load the serialized key and return a key interface."""


class BasePrivateKey(BaseAsymmetricKey):
    """Represents the base interface for private key."""
    @abstractmethod
    def signer(self):
        """Instantiate and return a signer object."""


class BasePublicKey(BaseAsymmetricKey):
    """Represents the base interface for public key."""
    @abstractmethod
    def verifier(self):
        """Instantiate and return a verifier object."""


# ===========================================================
# Decorators and utils for simplifying the creation of cipher wrappers.


def finalizer(f=None, *, allow=False):
    """Finalizes the cipher.

    Args:
        f: The method to wrap.
        allow:
            setting `allow` to True means that this function can
            be called multiple times even after finalization.

    Returns:
        The wrapped function.
    """
    if f is None:
        return partial(finalizer, allow=allow)

    @wraps(f)
    def wrapper(self, *args, **kwargs):
        if hasattr(self, '_done_') and not allow:
            raise exc.AlreadyFinalized("cipher has already been finalized")

        try:
            return f(self, *args, **kwargs)
        finally:
            if sys.exc_info()[0] in (exc.DecryptionError, None):
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
        raise exc.AlreadyFinalized(
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
        raise TypeError(f"Class must be derived from `{Cipher.__name__}`")

    # decorate methods
    cls.finalize = finalizer(cls.finalize)
    cls.calculate_tag = after_finalized(cls.calculate_tag)
    cls.authenticate = before_finalized(cls.authenticate)
    cls.update = before_finalized(cls.update)
    cls.update_into = before_finalized(cls.update_into)

    return cls
