from __future__ import annotations

import typing

from Cryptodome.PublicKey import RSA

from ... import base, exc
from ..asymmetric import OAEP, PSS
from .asymmetric import (
    ENCODINGS,
    FORMATS,
    PROTECTION_SCHEMES,
    get_padding_func,
)


class _RSAKey:
    @property
    def n(self) -> int:
        """RSA public modulus.

        The number ``n`` is such that ``n == p * q``.
        """
        return self._key.n

    @property
    def e(self) -> int:
        """RSA public exponent."""
        return self._key.e


class RSAPrivateKey(_RSAKey, base.BasePrivateKey):
    """RSA private key wrapper class."""

    def __init__(self, n: int, e: int = 65537, **kwargs):
        if kwargs:
            self._key = kwargs.pop("key")
        else:
            self._key = RSA.generate(n, e=e)

    @property
    def p(self) -> int:
        """First factor of RSA modulus."""
        return self._key.p

    @property
    def q(self) -> int:
        """Second factor of RSA modulus."""
        return self._key.q

    @property
    def d(self) -> int:
        """RSA private exponent."""
        return self._key.d

    def decryptor(self, padding=OAEP()) -> _EncDecContext:
        """Creates a decryption context.

        Args:
            padding: The padding to use. Default is OAEP.

        Returns:
            _EncDecContext: object for decrypting ciphertexts.
        """
        return _EncDecContext(
            True, get_padding_func(padding)(self._key, padding)
        )

    def signer(self, padding=PSS()) -> _SigVerContext:
        """Create a signer context.

        Args:
            padding: The padding to use. Default is PSS.

        Returns:
            _SigVerContext: Signer object for signing messages.

        Note:
            If the padding is PSS and ``salt_length`` is None, the salt length
            will be maximized, as in OpenSSL.
        """
        return _SigVerContext(
            True, get_padding_func(padding)(self._key, padding)
        )

    def public_key(self) -> RSAPublicKey:
        """Creates a public key from the private key.

        Returns:
            RSAPublicKey: The RSA public key.
        """
        return RSAPublicKey(self._key.publickey())

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "PKCS8",
        passphrase: typing.Optional[typing.ByteString] = None,
        *,
        protection: str = None,
    ) -> bytes:
        """Serialize the private key.

        Args:
            encoding (str):
                PEM or DER (defaults to PEM).
            format (str):
                PKCS1 or PKCS8 (defaults to PKCS8).
            passphrase (bytes, bytearray, memoryview):
                a bytes object to use for encrypting the private key.
                If ``passphrase`` is None, the private key will be exported
                in the clear!

        Keyword Arguments:
            protection (str):
                The protection scheme to use.

                Supplying a value for protection has meaning only if the
                ``format`` is PKCS8. If ``None`` is provided
                ``PBKDF2WithHMAC-SHA1AndAES256-CBC`` is used as the protection
                scheme.

        Returns:
            bytes: Serialized key as a bytes object.

        Raises:
            ValueError:
                If the encoding or format is incorrect or,
                if DER is used with PKCS1 or,
                protection value is supplied with PKCS1 format.
        """
        if encoding not in ENCODINGS.keys() ^ {"OpenSSH"}:
            raise ValueError("encoding must be PEM or DER")

        if protection is not None:
            if protection not in PROTECTION_SCHEMES:
                raise ValueError("invalid protection scheme")

        if format == "PKCS1":
            if protection is not None:
                raise ValueError("protection is meaningful only for PKCS8")
            if encoding == "DER":
                raise ValueError("cannot use DER with PKCS1 format")

        if passphrase is not None and protection is None:
            # use a curated encryption choice and not DES-EDE3-CBC
            protection = "PBKDF2WithHMAC-SHA1AndAES256-CBC"

        try:
            return self._key.export_key(
                format=ENCODINGS[encoding],
                pkcs=FORMATS[format],
                passphrase=(
                    memoryview(passphrase).tobytes()
                    if passphrase is not None
                    else None
                ),
                protection=protection,
            )
        except KeyError as e:
            raise ValueError(f"Invalid encoding or format: {e.args}") from e

    @classmethod
    def load(
        cls,
        data: typing.ByteString,
        passphrase: typing.Optional[typing.ByteString] = None,
    ) -> RSAPrivateKey:
        """Loads the private key as `bytes` object and returns the
        Key interface.

        Args:
            data (bytes):
                The key as bytes object.
            passphrase (bytes, bytearray, memoryview):
                The passphrase that deserializes the private key. ``passphrase``
                must be a ``bytes`` object if the key was encrypted while
                serialization, otherwise ``None``.

        Returns:
            RSAPrivateKey: The RSA private key.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        try:
            key = RSA.import_key(data, passphrase)
            if not key.has_private():
                raise ValueError("The key is not a private key")
            return cls(None, key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Either Key format is invalid or "
                "passphrase is missing or incorrect."
            ) from e


class RSAPublicKey(_RSAKey, base.BasePublicKey):
    """RSA Public Key wrapper class."""

    def __init__(self, key):
        self._key = key

    def encryptor(self, padding=OAEP()) -> _EncDecContext:
        """Creates a encryption context.

        Args:
            padding: The padding to use. Defaults to OAEP.

        Returns:
            _EncDecContext: object for decrypting ciphertexts.
        """
        return _EncDecContext(
            False, get_padding_func(padding)(self._key, padding)
        )

    def verifier(self, padding=PSS()) -> _SigVerContext:
        """Creates a verifier context.

        Args:
            padding: The padding to use. Defaults to ECC.

        Returns:
            _SigVerContext: verifier object for verification.

        Note:
            If the padding is PSS and ``salt_length`` is None, the salt length
            will be maximized, as in OpenSSL.
        """
        return _SigVerContext(
            False, get_padding_func(padding)(self._key, padding)
        )

    def serialize(self, encoding: str = "PEM") -> bytes:
        """Serialize the private key.

        Args:
            encoding (str): PEM, DER or OpenSSH (defaults to PEM).

        Returns:
            bytes: The serialized public key as bytes object.

        Raises:
            KeyError: if the encoding is not supported or invalid.
        """
        return self._key.export_key(format=ENCODINGS[encoding])

    @classmethod
    def load(cls, data: typing.ByteString) -> RSAPublicKey:
        """Loads the public key as `bytes` object and returns the
        Key interface.

        Args:
            data (bytes):
                The key as bytes object.

        Returns:
            RSAPublicKey: The public key.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        try:
            key = RSA.import_key(data)
            if key.has_private():
                raise ValueError("The key is not a public key")
            return cls(key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Key format might be invalid."
            ) from e


class _EncDecContext:
    def __init__(self, is_private, ctx):
        self._is_private = is_private
        self._ctx = ctx

    def encrypt(self, data):
        """Encrypts the plaintext and returns the ciphertext.

        Args:
            plaintext (bytes, bytearray):
                The data to encrypt.

        Returns:
            bytes: encrypted bytes object.
        """
        if self._is_private:
            raise TypeError("Only public keys can encrypt plaintexts.")
        return self._ctx.encrypt(data)

    def decrypt(self, data):
        """Decrypts the ciphertext and returns the plaintext.

        Args:
            ciphertext (bytes, bytearray):
                The ciphertext to decrypt.

        Returns:
            bytes: The plaintext.

        Raises:
            DecryptionError: if the decryption was not successful.
            TypeError: if the key is not a private key.
        """
        if not self._is_private:
            raise TypeError("Only private keys can decrypt ciphertexts.")
        try:
            return self._ctx.decrypt(data)
        except ValueError as e:
            raise exc.DecryptionError from e


class _SigVerContext:
    def __init__(self, is_private, ctx):
        self._is_private = is_private
        self._ctx = ctx

    def sign(self, msghash):
        """Return the signature of the message hash.

        Args:
            msghash (:class:`pyflocker.ciphers.base.BaseHash`):
                It must be a :any:`BaseHash` object, used to digest the
                message to sign.

        Returns:
            bytes: signature of the message as bytes object.
        """
        if not self._is_private:
            raise TypeError("Only private keys can sign messages.")
        return self._ctx.sign(msghash)

    def verify(self, msghash, signature):
        """Verifies the signature of the message hash.

        Args:
            msghash (:class:`pyflocker.ciphers.base.BaseHash`):
                It must be a :any:`BaseHash` object, used to digest the
                message to sign.

            signature (bytes, bytearray): The signature of the message.

        Returns:
            None

        Raises:
            SignatureError: if the signature was incorrect.
        """
        if self._is_private:
            raise TypeError("Only public keys can verify messages.")
        if not self._ctx.verify(msghash, signature):
            raise exc.SignatureError


def generate(bits: int, e: int = 65537) -> RSAPrivateKey:
    """
    Generate a private key with given key modulus ``bits`` and public exponent
    ``e`` (default 65537).
    Recommended size of ``bits`` > 1024.

    Args:
        bits (int): The bit length of the RSA key.
        e (int): The public exponent value. Default is 65537.

    Returns:
        RSAPrivateKey: The RSA private key.
    """
    return RSAPrivateKey(bits, e)


def load_public_key(data: typing.ByteString) -> RSAPublicKey:
    """Loads the public key and returns a Key interface.

    Args:
        data (bytes, bytearray):
            The public key (a bytes-like object) to deserialize.

    Returns:
        RSAPublicKey: The RSA public key.
    """
    return RSAPublicKey.load(data)


def load_private_key(
    data: typing.ByteString,
    passphrase: typing.Optional[typing.ByteString] = None,
) -> RSAPrivateKey:
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    ``passphrase`` must be ``None``, otherwise it must be a ``bytes`` object.

    Args:
        data (bytes, bytearray):
            The private key (a bytes-like object) to deserialize.
        passphrase (bytes, bytearray):
            The passphrase that was used to encrypt the private key.
            ``None`` if the private key was not encrypted.

    Returns:
        RSAPrivateKey: The RSA private key.
    """
    return RSAPrivateKey.load(data, passphrase)
