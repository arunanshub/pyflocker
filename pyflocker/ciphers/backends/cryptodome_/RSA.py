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
    _key: RSA.RsaKey

    @property
    def n(self) -> int:
        return self._key.n

    @property
    def e(self) -> int:
        return self._key.e


class RSAPrivateKey(_RSAKey, base.BaseRSAPrivateKey):
    """RSA private key wrapper class."""

    def __init__(self, n: int, e: int = 65537, **kwargs):
        if kwargs:
            self._key = kwargs.pop("key")
        else:
            self._key = RSA.generate(n, e=e)

    @property
    def p(self) -> int:
        return self._key.p

    @property
    def q(self) -> int:
        return self._key.q

    @property
    def d(self) -> int:
        return self._key.d

    def decryptor(self, padding=OAEP()) -> DecryptorContext:
        return DecryptorContext(
            get_padding_func(padding)(self._key, padding),
        )

    def signer(self, padding=PSS()) -> SignerContext:
        return SignerContext(
            get_padding_func(padding)(self._key, padding),
        )

    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self._key.publickey())

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "PKCS8",
        passphrase: typing.Optional[bytes] = None,
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
                    memoryview(passphrase).tobytes()  # type: ignore
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
        data: bytes,
        passphrase: typing.Optional[bytes] = None,
    ) -> RSAPrivateKey:
        """Loads the private key as `bytes` object and returns the
        Key interface.

        Args:
            data (bytes):
                The key as bytes object.
            passphrase (bytes, bytearray, memoryview):
                The passphrase that deserializes the private key.
                ``passphrase`` must be a ``bytes`` object if the key was
                encrypted while serialization, otherwise ``None``.

        Returns:
            RSAPrivateKey: The RSA private key.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        try:
            key = RSA.import_key(data, passphrase)  # type: ignore
            if not key.has_private():
                raise ValueError("The key is not a private key")
            return cls(None, key=key)  # type: ignore
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Either Key format is invalid or "
                "passphrase is missing or incorrect."
            ) from e


class RSAPublicKey(_RSAKey, base.BaseRSAPublicKey):
    """RSA Public Key wrapper class."""

    def __init__(self, key):
        self._key = key

    def encryptor(self, padding=OAEP()) -> EncryptorContext:
        return EncryptorContext(
            get_padding_func(padding)(self._key, padding),
        )

    def verifier(self, padding=PSS()) -> VerifierContext:
        return VerifierContext(
            get_padding_func(padding)(self._key, padding),
        )

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "SubjectPublicKeyInfo",
    ) -> bytes:
        """Serialize the private key.

        Args:
            encoding (str): PEM, DER or OpenSSH (defaults to PEM).
            format: The supported formats are:

                - SubjectPublicKeyInfo
                - OpenSSH

                Note:
                    ``format`` argument is not actually used by Cryptodome. It
                    is here to maintain compatibility with pyca/cryptography
                    backend counterpart.

        Returns:
            bytes: The serialized public key as bytes object.

        Raises:
            KeyError: if the encoding or format is not supported or invalid.
        """
        if format not in ("SubjectPublicKeyInfo", "OpenSSH"):
            raise KeyError("Invalid format")
        if format == "OpenSSH" and encoding != "OpenSSH":
            raise ValueError(
                "OpenSSH format can be used only with OpenSSH encoding",
            )
        return self._key.export_key(format=ENCODINGS[encoding])

    @classmethod
    def load(cls, data: bytes) -> RSAPublicKey:
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


class EncryptorContext(base.BaseEncryptorContext):
    def __init__(self, ctx):
        self._ctx = ctx

    def encrypt(self, data):
        return self._ctx.encrypt(data)


class DecryptorContext(base.BaseDecryptorContext):
    def __init__(self, ctx):
        self._ctx = ctx

    def decrypt(self, data):
        try:
            return self._ctx.decrypt(data)
        except ValueError as e:
            raise exc.DecryptionError from e


class SignerContext(base.BaseSignerContext):
    def __init__(self, ctx):
        self._ctx = ctx

    def sign(self, msghash):
        return self._ctx.sign(msghash)


class VerifierContext(base.BaseVerifierContext):
    def __init__(self, ctx):
        self._ctx = ctx

    def verify(self, msghash, signature):
        try:
            self._ctx.verify(msghash, signature)
        except ValueError as e:
            raise exc.SignatureError from e


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


def load_public_key(data: bytes) -> RSAPublicKey:
    """Loads the public key and returns a Key interface.

    Args:
        data (bytes, bytearray):
            The public key (a bytes-like object) to deserialize.

    Returns:
        RSAPublicKey: The RSA public key.
    """
    return RSAPublicKey.load(data)


def load_private_key(
    data: bytes,
    passphrase: typing.Optional[bytes] = None,
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
