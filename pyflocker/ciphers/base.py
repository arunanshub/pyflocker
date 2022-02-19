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
            ``True`` if encrypting, else ``False``.
        """

    @abstractmethod
    def update(self, data: bytes) -> bytes:
        """Takes bytes-like object and returns encrypted/decrypted
        bytes object.

        Args:
            data: The bytes-like object to pass to the cipher.

        Returns:
            Encrypted data as bytes.
        """

    @abstractmethod
    def update_into(
        self,
        data: bytes,
        out: typing.Union[bytearray, memoryview],
    ) -> None:
        """
        Encrypt or decrypt the ``data`` and store it in a preallocated buffer
        ``out``.

        Args:
            data: The bytes-like object to pass to the cipher.
            out:
                The buffer interface where the encrypted/decrypted data must be
                written into.
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

    Custom cipher wrappers that provide AEAD functionality to NonAEAD ciphers
    must derive from this.
    """

    __slots__ = ()

    @abstractmethod
    def authenticate(self, data: bytes) -> None:
        """Authenticates part of the message that get delivered as is, without
        any encryption.

        Args:
            data: The bytes-like object that must be authenticated.

        Raises:
            TypeError:
                if this method is called after calling
                :py:meth:`~BaseSymmetricCipher.update`.
        """

    @abstractmethod
    def finalize(self, tag: typing.Optional[bytes] = None) -> None:
        """Finalizes and ends the cipher state.

        Args:
            tag:
                The associated tag that authenticates the decryption. Tag is
                required for decryption only.

        Raises:
            ValueError: If cipher is decrypting and tag is not supplied.
            DecryptionError: If the decryption was incorrect.
        """

    @abstractmethod
    def calculate_tag(self) -> typing.Optional[bytes]:
        """Calculates and returns the associated tag.

        Returns:
            Returns ``None`` if decrypting, otherwise the associated
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
        bytes. If the hash has a variable output size, this output size must be
        chosen when the hashing object is created, and this attribute must
        contain the selected size. Therefore, None is not a legal value for
        this attribute.

        Returns:
            Digest size as integer.
        """

    @property
    @abstractmethod
    def block_size(self) -> int:
        """
        An integer value or :any:`NotImplemented`; the internal block size of
        the hash algorithm in bytes. The block size is used by the HMAC module
        to pad the secret key to digest_size or to hash the secret key if it is
        longer than digest_size. If no HMAC algorithm is standardized for the
        hash algorithm, returns :any:`NotImplemented` instead.

        Returns:
            An integer if block size is available, otherwise
            :any:`NotImplemented`.

        See Also:
            PEP 452 -- API for Cryptographic Hash Functions v2.0,
            https://www.python.org/dev/peps/pep-0452
        """

    @abstractmethod
    def update(self, data: bytes) -> None:
        """
        Hash string into the current state of the hashing object. ``update()``
        can be called any number of times during a hashing object's lifetime.

        Args:
            data: The chunk of message being hashed.

        Raises:
            AlreadyFinalized:
                Raised if :py:meth:`~digest` or :py:meth:`~hexdigest` has been
                called.
        """

    @abstractmethod
    def digest(self) -> bytes:
        """
        Return the hash value of this hashing object as a string containing
        8-bit data. The object is not altered in any way by this function; you
        can continue updating the object after calling this function.

        Returns:
            Digest as binary form.
        """

    def hexdigest(self) -> str:
        """
        Return the hash value of this hashing object as a string containing
        hexadecimal digits.

        Returns:
            Digest, as a hexadecimal form.
        """
        return self.digest().hex()

    @abstractmethod
    def copy(self) -> BaseHash:
        """
        Return a separate copy of this hashing object.
        An update to this copy won't affect the original object.

        Returns:
            A copy of hash function.

        Raises:
            AlreadyFinalized:
                This is raised if the method is called after calling
                :py:meth:`~digest` method.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the hash function."""

    @abstractmethod
    def new(self, data=b"") -> BaseHash:
        """Create a fresh hash object."""

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} '{self.name}' at {hex(id(self))}>"


class BasePrivateKey(metaclass=ABCMeta):
    ...


class BasePublicKey(metaclass=ABCMeta):
    ...


class BaseRSAPrivateKey(metaclass=ABCMeta):
    @property
    @abstractmethod
    def n(self) -> int:
        """RSA public modulus.

        The number `n` is such that `n == p * q`.
        """

    @property
    @abstractmethod
    def e(self) -> int:
        """RSA public exponent."""

    @property
    @abstractmethod
    def p(self) -> int:
        """First factor of RSA modulus."""

    @property
    @abstractmethod
    def q(self) -> int:
        """Second factor of RSA modulus."""

    @property
    @abstractmethod
    def d(self) -> int:
        """RSA private exponent."""

    @property
    @abstractmethod
    def key_size(self):
        """Size of the key, in bits."""

    @abstractmethod
    def decryptor(self, padding) -> BaseDecryptorContext:
        """Creates a decryption context.

        Args:
            padding: The padding to use. Default is OAEP.

        Returns:
            object for decrypting ciphertexts.
        """

    @abstractmethod
    def signer(self, padding) -> BaseSignerContext:
        """Create a signer context.

        Args:
            padding: The padding to use. Default is PSS.

        Returns:
            Signer object for signing messages.

        Note:
            If the padding is PSS and ``salt_length`` is None, the salt length
            will be maximized, as in OpenSSL.
        """

    @abstractmethod
    def public_key(self) -> BaseRSAPublicKey:
        """Creates a public key from the private key.

        Returns:
            The RSA public key.
        """

    @abstractmethod
    def serialize(
        self,
        encoding: str,
        format: str,
        passphrase: typing.Optional[bytes] = None,
    ) -> bytes:
        """Serialize the private key.

        Args:
            encoding: The encoding to use.
            format: The format to use.
            passphrase:
                A bytes object to use for encrypting the private key. If
                ``passphrase`` is None, the private key will be exported in the
                clear!

        Returns:
            Serialized key as a bytes object.

        Raises:
            ValueError: If the encoding or format is incorrect.

        Important:
            The ``encoding`` and ``format`` supported by one backend may not be
            supported by the other. You should check the documentation of the
            implementation of the method for supported options.
        """

    @classmethod
    @abstractmethod
    def load(
        cls,
        data: bytes,
        passphrase: typing.Optional[bytes] = None,
    ) -> BaseRSAPrivateKey:
        """Loads the private key as bytes object and returns the Key interface.

        Args:
            data: The key as bytes object.
            passphrase:
                The passphrase that deserializes the private key. It must be a
                bytes-like object if the key was encrypted while serialization,
                otherwise ``None``.

        Returns:
            RSA private key.

        Raises:
            ValueError: if the key could not be deserialized.
        """


class BaseRSAPublicKey(metaclass=ABCMeta):
    @property
    @abstractmethod
    def n(self) -> int:
        """RSA public modulus.

        The number `n` is such that `n = p * q`.
        """

    @property
    @abstractmethod
    def e(self) -> int:
        """RSA public exponent."""

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Size of the key, in bits."""

    @abstractmethod
    def encryptor(self, padding) -> BaseEncryptorContext:
        """Creates a encryption context.

        Args:
            padding: The padding to use. Defaults to OAEP.

        Returns:
            object for encrypting plaintexts.
        """

    @abstractmethod
    def verifier(self, padding) -> BaseVerifierContext:
        """Creates a verifier context.

        Args:
            padding: The padding to use. Defaults to PSS.

        Returns:
            verifier object for verification.
        """

    @abstractmethod
    def serialize(
        self,
        encoding: str,
        format: str,
    ) -> bytes:
        """Serialize the public key.

        Args:
            encoding: The encoding to use.
            format: The format to use.

        Returns:
            Serialized public key as bytes object.

        Raises:
            KeyError: if the encoding or format is incorrect or unsupported.

        Important:
            The ``encoding`` and ``format`` supported by one backend may not be
            supported by the other. You should check the documentation of the
            implementation of this method for supported options.
        """

    @classmethod
    @abstractmethod
    def load(cls, data: bytes) -> BaseRSAPublicKey:
        """Loads the public key as ``bytes`` object and returns
        the Key interface.

        Args:
            data: The key as bytes object.

        Returns:
            The RSA public key.

        Raises:
            ValueError: if the key could not be deserialized.
        """


class BaseSignerContext(metaclass=ABCMeta):
    @abstractmethod
    def sign(self, msghash: BaseHash) -> bytes:
        """Return the signature of the message hash.

        Args:
            msghash:
                It must be a :any:`BaseHash` object, used to digest the message
                to sign.

        Returns:
            signature of the message as bytes object.
        """


class BaseVerifierContext(metaclass=ABCMeta):
    @abstractmethod
    def verify(self, msghash: BaseHash, signature: bytes):
        """Verifies the signature of the message hash.

        Args:
            msghash:
                It must be a :any:`BaseHash` object, used to digest the message
                to sign.

            signature: The signature of the message.

        Raises:
            SignatureError: if the signature was incorrect.
        """


class BaseEncryptorContext(metaclass=ABCMeta):
    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypts the plaintext and returns the ciphertext.

        Args:
            plaintext: The data to encrypt.

        Returns:
            encrypted bytes object.
        """


class BaseDecryptorContext(metaclass=ABCMeta):
    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypts the ciphertext and returns the plaintext.

        Args:
            ciphertext: The ciphertext to decrypt.

        Returns:
            The plaintext.

        Raises:
            DecryptionError: if the decryption was not successful.
        """


class BaseDHParameters(metaclass=ABCMeta):
    @property
    @abstractmethod
    def g(self) -> int:
        """The generator value."""

    @property
    @abstractmethod
    def p(self) -> int:
        """The prime modulus value."""

    @property
    @abstractmethod
    def q(self) -> typing.Optional[int]:
        """The p subgroup order value."""

    @abstractmethod
    def private_key(self) -> BaseDHPrivateKey:
        """Create a DH private key from the parameters.

        Returns:
            A private key object.
        """

    @abstractmethod
    def serialize(self, encoding: str, format: str) -> bytes:
        """Serialize the DH parameters.

        Args:
            encoding: The encoding to use.
            format: The format to use.

        Returns:
            The parameters encoded as bytes object.

        Raises:
            ValueError: if the encoding of format is invalid.

        Important:
            The ``encoding`` and ``format`` supported by one backend may not be
            supported by the other. You should check the documentation of the
            implementation of this method for supported options.
        """

    @classmethod
    @abstractmethod
    def load(cls, data: bytes) -> BaseDHParameters:
        """Deserialize the encoded DH parameters.

        Args:
            data: The parameters as an encoded bytes object.

        Returns:
            DH parameter object.
        """

    @classmethod
    @abstractmethod
    def load_from_parameters(
        cls,
        p: int,
        g: int = 2,
        q: typing.Optional[int] = None,
    ) -> BaseDHParameters:
        """Generates a DH parameter group from the parameters.

        Args:
            p: The prime modulus value.
            g: The generator value. Must be 2 or 5. Default is 2.
            q: p subgroup order value. Defaults to ``None``.

        Returns:
            DH Parameter object.
        """


class BaseDHPrivateKey(metaclass=ABCMeta):
    @abstractmethod
    def parameters(self) -> BaseDHParameters:
        """Creates a new DH Parameters object from the key.

        Returns:
            The DH parameter object.
        """

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Size of the key, in bytes."""

    @abstractmethod
    def public_key(self) -> BaseDHPublicKey:
        """Create a public key from the private key.

        Returns:
            A public key object.
        """

    @abstractmethod
    def exchange(
        self,
        peer_public_key: typing.Union[bytes, BaseDHPublicKey],
    ) -> bytes:
        """Perform a key exchange.

        Args:
            peer_public_key:
                The peer public key can be a bytes or a :any:`BaseDHPublicKey`
                object.

        Returns:
            A shared key.

        Raises:
            TypeError:
                if ``peer_public_key`` is not a bytes-like or DH Public Key
                object.
        """

    @abstractmethod
    def serialize(
        self,
        encoding: str,
        format: str,
        passphrase: typing.Optional[bytes],
    ) -> bytes:
        """Serialize the private key.

        Args:
            encoding: The encoding to use.
            format: The format to use.
            passphrase:
                The passphrase to use to protect the private key. ``None`` if
                the private key is not encrypted.

        Returns:
            The private key as bytes object.

        Raises:
            ValueError: if the encoding or format is invalid.
            TypeError: if the passphrase is not a bytes-like object.

        Important:
            The ``encoding`` and ``format`` supported by one backend may not be
            supported by the other. You should check the documentation of the
            implementation of this method for supported options.
        """

    @property
    @abstractmethod
    def x(self) -> int:
        """The private value."""

    @classmethod
    @abstractmethod
    def load(
        cls,
        data: bytes,
        passphrase: typing.Optional[bytes] = None,
    ) -> BaseDHPrivateKey:
        """Deserialize and load the the private key.

        Args:
            data: The serialized private key as bytes-like object.
            passphrase:
                The passphrase that was used to protect the private key. If key
                is not protected, passphrase is ``None``.

        Returns:
            A private key.

        Raises:
            ValueError: If the key could not be deserialized.
            TypeError: If passphrase is not a bytes-like object.
        """


class BaseDHPublicKey(metaclass=ABCMeta):
    @abstractmethod
    def parameters(self) -> BaseDHParameters:
        """Creates a new DH parameters object from the key.

        Returns:
            The DH parameter object.
        """

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Size of the key, in bytes."""

    @abstractmethod
    def serialize(
        self,
        encoding: str,
        format: str,
    ) -> bytes:
        """Serialize the public key.

        Args:
            encoding: The encoding to use.
            format: The format to use.

        Returns:
            The public key as bytes object.

        Raises:
            ValueError: if the encoding or format is invalid.
        """

    @property
    @abstractmethod
    def y(self) -> int:
        """The public value."""

    @classmethod
    @abstractmethod
    def load(cls, data: bytes) -> BaseDHPublicKey:
        """Deserialize and load the public key.

        Args:
            data: The serialized public key as bytes-like object.

        Returns:
            A public key object.

        Raises:
            ValueError: If the key could not be deserialized.
        """
