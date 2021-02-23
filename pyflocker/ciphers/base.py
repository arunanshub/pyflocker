"""Base classes for pyflocker."""

from __future__ import annotations

import typing
from abc import ABCMeta, abstractmethod


class BaseSymmetricCipher(metaclass=ABCMeta):
    __slots__ = ()

    @abstractmethod
    def is_encrypting(self) -> bool:
        """Whether the cipher is encrypting or not.

        Returns:
            bool: True if encrypting, else False.
        """

    @abstractmethod
    def update(self, data: typing.ByteString) -> bytes:
        """Takes bytes-like object and returns encrypted/decrypted
        bytes object.

        Args:
            data (bytes, bytearray):
                The bytes-like object to pass to the cipher.

        Returns:
            bytes: bytes-like encrypted data.
        """

    @abstractmethod
    def update_into(
        self,
        data: typing.ByteString,
        out: typing.ByteString,
    ) -> None:
        """Encrypt or decrypt the `data` and store it in a preallocated buffer
        `out`.

        Args:
            data (bytes, bytearray, memoryview):
                The bytes-like object to pass to the cipher.
            out (bytearray, memoryview):
                The buffer interface where the encrypted/decrypted data
                must be written into.
        """


class BaseNonAEADCipher(BaseSymmetricCipher):
    """
    Abstract Base Class for ciphers that have no authentication support.

    These ciphers can be wrapped by classes that implement ``BaseAEADCipher``
    and the wrappers must provide authentication support.
    """

    __slots__ = ()

    @abstractmethod
    def finalize(self) -> None:
        """Finalizes and closes the cipher.

        Raises:
            AlreadyFinalized: If the cipher was already finalized.
        """


class BaseAEADCipher(BaseSymmetricCipher):
    """Abstract base class for AEAD ciphers.

    Custom cipher wrappers that provide AEAD functionality to NonAEAD
    ciphers must derive from this.
    """

    __slots__ = ()

    @abstractmethod
    def authenticate(self, data: typing.ByteString) -> None:
        """Authenticates part of the message that get delivered as is, without
        any encryption.

        Args:
            data (bytes, bytearray, memoryview):
                The bytes-like object that must be authenticated.

        Raises:
            TypeError:
                if this method is called after calling
                :py:attr:`~BaseAEADCipher.update`.
        """

    @abstractmethod
    def finalize(self, tag: typing.Optional[typing.ByteString] = None) -> None:
        """Finalizes and ends the cipher state.

        Args:
            tag (bytes, bytearray):
                The associated tag that authenticates the decryption.
                `tag` is required for decryption only.

        Raises:
            ValueError: If cipher is decrypting and tag is not supplied.
            DecryptionError: If the decryption was incorrect.
        """

    @abstractmethod
    def calculate_tag(self) -> typing.Optional[bytes]:
        """Calculates and returns the associated `tag`.

        Returns:
            Union[None, bytes]:
                Returns None if decrypting, otherwise the associated
                authentication tag.
        """


class BaseHash(metaclass=ABCMeta):
    """Abstract base class for hash functions. Follows PEP-0452.

    Custom MACs must use this interface.
    """

    __slots__ = ()

    @property
    @abstractmethod
    def digest_size(self) -> int:
        """
        The size of the digest produced by the hashing object, measured in
        bytes. If the hash has a variable output size, this output size must
        be chosen when the hashing object is created, and this attribute must
        contain the selected size. Therefore, None is not a legal value for
        this attribute.

        Returns:
            int: Digest size as integer.
        """

    @property
    @abstractmethod
    def block_size(self) -> typing.Union[int, NotImplemented]:
        """
        An integer value or NotImplemented; the internal block size of the hash
        algorithm in bytes. The block size is used by the HMAC module to pad
        the secret key to digest_size or to hash the secret key if it is longer
        than digest_size. If no HMAC algorithm is standardized for the hash
        algorithm, returns ``NotImplemented`` instead.

        See Also:
            PEP 452 -- API for Cryptographic Hash Functions v2.0,
            https://www.python.org/dev/peps/pep-0452

        Returns:
            Union[int, NotImplemented]:
                An integer if block size is available, otherwise
                ``NotImplemented``
        """

    @abstractmethod
    def update(self, data: typing.ByteString) -> None:
        """
        Hash string into the current state of the hashing object. ``update()``
        can be called any number of times during a hashing object's lifetime.

        Args:
            data (bytes, bytearray, memoryview):
                The chunk of message being hashed.

        Raises:
            AlreadyFinalized:
                This is raised if ``digest`` or ``hexdigest`` has been called.
        """

    @abstractmethod
    def digest(self) -> bytes:
        """
        Return the hash value of this hashing object as a string containing
        8-bit data. The object is not altered in any way by this function; you
        can continue updating the object after calling this function.

        Returns:
            bytes: Digest as binary form.
        """

    def hexdigest(self) -> str:
        """
        Return the hash value of this hashing object as a string containing
        hexadecimal digits.

        Returns:
            str: Digest, as a hexadecimal form.
        """
        return self.digest().hex()

    @abstractmethod
    def copy(self) -> BaseHash:
        """
        Return a separate copy of this hashing object.
        An update to this copy won't affect the original object.

        Returns:
            BaseHash: a copy of hash function.

        Raises:
            AlreadyFinalized:
                This is raised if the method is called after calling
                `~BaseHash.digest` method.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the hash function.

        Returns:
            str: Name of hash function.
        """

    @abstractmethod
    def new(self, data=b"", *args, **kwargs) -> BaseHash:
        """Create a fresh hash object."""

    def __repr__(self) -> str:
        return f"<{type(self).__name__} '{self.name}' at {hex(id(self))}>"


class BasePrivateKey(metaclass=ABCMeta):
    __slots__ = ()

    @abstractmethod
    def serialize(
        self,
        passphrase: typing.Optional[typing.ByteString] = None,
        *args,
        **kwargs,
    ) -> bytes:
        """Serialize the private key into a bytes object.

        Args:
            passphrase (bytes, bytearray, memoryview):
                The passphrase to use to protect (encrypt) the key.

        Returns:
            bytes: The binary representation of the key.
        """

    @classmethod
    @abstractmethod
    def load(
        cls,
        passphrase: typing.Optional[typing.ByteString] = None,
        *args,
        **kwargs,
    ) -> BasePrivateKey:
        """Load (or deserialize) the key into a key object.

        Args:
            passphrase (bytes):
                The passphrase to decrypt the private key. Without a passphrase,
                the key is not encrypted.

        Returns:
            BaseAsymmetricKey: A key object.
        """


class BasePublicKey(metaclass=ABCMeta):
    __slots__ = ()

    @abstractmethod
    def serialize(
        self,
        *args,
        **kwargs,
    ) -> bytes:
        """Serialize the public key into a bytes object.

        Returns:
            bytes: The binary representation of the public key.
        """

    @classmethod
    @abstractmethod
    def load(cls, *args, **kwargs) -> BasePublicKey:
        """Load (or deserialize) the key into a key object.

        Returns:
            BasePublicKey: A key object.
        """
