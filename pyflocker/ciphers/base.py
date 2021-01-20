"""Base classes for pyflocker."""

import sys
import typing

from functools import wraps, partial
from abc import ABCMeta, abstractmethod

from . import exc


class BaseCipher(metaclass=ABCMeta):
    @abstractmethod
    def is_encrypting(self) -> bool:
        """Whether the cipher is encrypting or not.

        Args:
            None

        Returns:
            bool: True if encrypting, else False.
        """


class BaseNonAEADCipher(BaseCipher):
    @abstractmethod
    def update(self, data: typing.ByteString) -> bytes:
        """Takes bytes-like object and returns encrypted/decrypted
        bytes object.

        Args:
            data (bytes, bytesarray):
                The bytes-like object to pass to the cipher.

        Returns:
            bytes: bytes-like encrypted data.
        """

    @abstractmethod
    def update_into(self, data, out) -> None:
        """Encrypt or decrypt the `data` and store it in a preallocated buffer
        `out`.

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
    def finalize(self) -> None:
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
    def update(self, data) -> bytes:
        """Takes bytes-like object and returns encrypted/decrypted
        bytes object, while passing it through the MAC.

        Args:
            data (bytes, bytesarray):
                The bytes-like object to pass to the cipher.

        Returns:
            bytes: bytes-like encrypted data.
        """

    @abstractmethod
    def update_into(self, data, out) -> None:
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
    def authenticate(self, data: typing.ByteString) -> None:
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
    def finalize(self, tag: typing.Optional[typing.ByteString] = None) -> None:
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
    def calculate_tag(self) -> bytes:
        """Calculates and returns the associated `tag`.

        Args:
            None

        Returns:
            If encrypting, it returns `None`, otherwise a `bytes` object.
        """
