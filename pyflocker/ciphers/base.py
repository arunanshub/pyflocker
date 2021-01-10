"""Base classes for pyflocker."""

import sys

from functools import wraps, partial
from abc import ABCMeta, abstractmethod

from . import exc


class BaseCipher(metaclass=ABCMeta):
    @abstractmethod
    def is_encrypting(self):
        """Whether the cipher is encrypting or not."""


class BaseNonAEADCipher(BaseCipher):
    @abstractmethod
    def update(self, data):
        """Takes bytes-like object and returns encrypted/decrypted
        bytes object.
        Args:
            data (bytes, bytesarray):
                The bytes-like object to pass to the cipher.
        Returns:
            bytes: bytes-like encrypted data.
        """

    @abstractmethod
    def update_into(self, data, out):
        """Works almost like :py:attr:`~Cipher.update` method, except for
        it fills a preallocated buffer with data with no intermideate
        copying of data.
        Args:
            data (bytes, bytearray, memoryview):
                The bytes-like object to pass to the cipher.
            out (bytearray, memoryview):
                The buffer interface where the encrypted/decrypted data
                must be written into.
        Returns:
            None
        """

    @abstractmethod
    def finalize(self):
        """Finalizes and closes the cipher.

        Returns:
            None
        Raises:
            AlreadyFinalized: If the cipher was already finalized.
        """


class BaseAEADCipher(BaseCipher):
    """Abstract base class for AEAD ciphers.

    Custom cipher wrappers that provide AEAD functionality to NonAEAD
    ciphers must derive from this.
    """

    @abstractmethod
    def update(self, data):
        """Takes bytes-like object and returns encrypted/decrypted
        bytes object, while passing it through the MAC.
        Args:
            data (bytes, bytesarray):
                The bytes-like object to pass to the cipher.
        Returns:
            bytes: bytes-like encrypted data.
        """

    @abstractmethod
    def update_into(self, data, out):
        """Works almost like :py:attr:`~Cipher.update` method, except for
        it fills a preallocated buffer with data with no intermideate
        copying of data. The data buffer is passed through the MAC.
        Args:
            data (bytes, bytearray, memoryview):
                The bytes-like object to pass to the cipher.
            out (bytearray, memoryview):
                The buffer interface where the encrypted/decrypted data
                must be written into.
        Returns:
            None
        """

    @abstractmethod
    def authenticate(self, data):
        """Authenticates additional data.
        Data must be a bytes, bytearray or memoryview object. You can call
        it to pass additional data that must be authenticated, but would be
        transmitted in the clear.
        Args:
            data (bytes, bytearray, memoryview):
                The bytes-like object that must be authenticated.
        Returns:
            None
        Raises:
            TypeError:
                if this method is called after calling :py:attr:`~Cipher.update`.
        """

    @abstractmethod
    def finalize(self, tag=None):
        """Finalizes and closes the cipher.
        Args:
            tag (bytes, bytearray):
                The associated tag that authenticates the decryption.
                `tag` is required for decryption only.
        Returns:
            None
        Raises:
            ValueError: If cipher is decrypting and tag is not supplied.
            DecryptionError: If the decryption was incorrect.
        """

    @abstractmethod
    def calculate_tag(self):
        """Calculates and returns the associated `tag`.
        Returns:
            If encrypting, it returns `None`, otherwise a `bytes` object.
        """
