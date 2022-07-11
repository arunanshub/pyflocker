from __future__ import annotations

import typing
from functools import partial

import cryptography.exceptions as bkx
from cryptography.hazmat.primitives import serialization as serial
from cryptography.hazmat.primitives.asymmetric import rsa, utils
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
)

from ... import base, exc
from ..asymmetric import OAEP, PSS
from . import Hash
from .asymmetric import get_padding_algorithm

if typing.TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import padding as _padding


class RSAPrivateKey(base.BaseRSAPrivateKey):
    # Encodings supported by this key.
    _ENCODINGS = {
        "PEM": Encoding.PEM,
        "DER": Encoding.DER,
    }

    # Formats supported by this key.
    _FORMATS = {
        "TraditionalOpenSSL": PrivateFormat.TraditionalOpenSSL,
        "PKCS1": PrivateFormat.TraditionalOpenSSL,
        "OpenSSH": PrivateFormat.OpenSSH,
        "PKCS8": PrivateFormat.PKCS8,
    }

    # Key loaders indexed by the key format.
    _LOADERS = {
        b"-----BEGIN OPENSSH PRIVATE KEY": serial.load_ssh_private_key,
        b"-----": serial.load_pem_private_key,
        b"0": serial.load_der_private_key,
    }

    def __init__(
        self,
        n: int | None,
        e: int = 65537,
        _key: rsa.RSAPrivateKey | None = None,
    ) -> None:
        if _key is not None:
            self._key = _key
        else:
            if not isinstance(n, int):  # pragma: no cover
                raise TypeError("n must be an integer value")
            self._key = rsa.generate_private_key(e, n)

        # numbers
        priv_nos = self._key.private_numbers()
        self._p = priv_nos.p
        self._q = priv_nos.q
        self._d = priv_nos.d

        pub_nos = priv_nos.public_numbers
        self._e = pub_nos.e
        self._n = pub_nos.n

    @property
    def p(self) -> int:
        return self._p

    @property
    def q(self) -> int:
        return self._q

    @property
    def d(self) -> int:
        return self._d

    @property
    def e(self) -> int:
        return self._e

    @property
    def n(self) -> int:
        return self._n

    @property
    def key_size(self) -> int:
        return self._key.key_size

    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self._key.public_key())

    def decryptor(
        self,
        padding: base.BaseAsymmetricPadding | None = None,
    ) -> DecryptorContext:
        if padding is None:  # pragma: no cover
            padding = OAEP()
        return DecryptorContext(
            self._key,
            get_padding_algorithm(padding, padding),
        )

    def signer(
        self,
        padding: base.BaseAsymmetricPadding | None = None,
    ) -> SignerContext:
        if padding is None:  # pragma: no cover
            padding = PSS()
        return SignerContext(
            self._key,
            get_padding_algorithm(padding, padding),
        )

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "PKCS8",
        passphrase: bytes | None = None,
    ) -> bytes:
        """Serialize the private key.

        Args:
            encoding: PEM or DER (defaults to PEM).
            format: The formats can be:

                - PKCS8 (default)
                - TraditionalOpenSSL
                - OpenSSH (available from pyca/cryptography version >=3.X)
                - PKCS1 (alias to TraditionalOpenSSL for Cryptodome compat)
            passphrase:
                A bytes-like object to protect the private key. If
                ``passphrase`` is None, the private key will be exported in the
                clear!

        Returns:
            The private key as a bytes object.

        Raises:
           ValueError: if the format or encoding is invalid or not supported.
        """
        try:
            encd = self._ENCODINGS[encoding]
            fmt = self._FORMATS[format]
        except KeyError as e:
            raise ValueError(
                f"The encoding or format is invalid: {e.args[0]!r}"
            ) from e

        protection: serial.KeySerializationEncryption
        if passphrase is None:
            protection = serial.NoEncryption()
        else:
            protection = serial.BestAvailableEncryption(
                memoryview(passphrase).tobytes()
            )

        try:
            return self._key.private_bytes(encd, fmt, protection)
        except ValueError as e:
            raise ValueError(f"Failed to serialize key: {e!s}") from e

    @classmethod
    def load(
        cls,
        data: bytes,
        passphrase: bytes | None = None,
    ) -> RSAPrivateKey:
        loader = cls._get_loader(data)

        if passphrase is not None:
            passphrase = memoryview(passphrase).tobytes()

        try:
            key = loader(memoryview(data), passphrase)
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError("Key is not an RSA Private key")
        except (ValueError, TypeError) as e:
            raise ValueError(f"Failed to load key: {e!s}") from e

        return cls(None, _key=key)

    @classmethod
    def _get_loader(cls, data: bytes) -> typing.Callable:
        """
        Returns a loader function depending on the initial bytes of the key.
        """
        try:
            return cls._LOADERS[next(filter(data.startswith, cls._LOADERS))]
        except StopIteration:
            raise ValueError("Invalid format") from None


class RSAPublicKey(base.BaseRSAPublicKey):
    # Encodings supported by this key.
    _ENCODINGS = {
        "PEM": Encoding.PEM,
        "DER": Encoding.DER,
        "OpenSSH": Encoding.OpenSSH,
    }

    # Formats supported by this key.
    _FORMATS = {
        "OpenSSH": PublicFormat.OpenSSH,
        "PKCS1": PublicFormat.PKCS1,
        "SubjectPublicKeyInfo": PublicFormat.SubjectPublicKeyInfo,
    }

    # Key loaders indexed by the key format.
    _LOADERS = {
        b"ssh-rsa ": serial.load_ssh_public_key,
        b"-----": serial.load_pem_public_key,
        b"0": serial.load_der_public_key,
    }

    def __init__(self, key: rsa.RSAPublicKey) -> None:
        if not isinstance(key, rsa.RSAPublicKey):  # pragma: no cover
            raise ValueError("The key is not an RSA public key.")
        self._key = key

        # numbers
        pub_nos = self._key.public_numbers()
        self._e = pub_nos.e
        self._n = pub_nos.n

    @property
    def e(self) -> int:
        return self._e

    @property
    def n(self) -> int:
        return self._n

    @property
    def key_size(self) -> int:
        return self._key.key_size

    def encryptor(
        self,
        padding: base.BaseAsymmetricPadding | None = None,
    ) -> EncryptorContext:
        if padding is None:  # pragma: no cover
            padding = OAEP()
        return EncryptorContext(
            self._key,
            get_padding_algorithm(padding, padding),
        )

    def verifier(
        self,
        padding: base.BaseAsymmetricPadding | None = None,
    ) -> VerifierContext:
        if padding is None:  # pragma: no cover
            padding = PSS()
        return VerifierContext(
            self._key,
            get_padding_algorithm(padding, padding),
        )

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "SubjectPublicKeyInfo",
    ) -> bytes:
        """Serialize the public key.

        Args:
            encoding: PEM, DER or OpenSSH (defaults to PEM).
            format: The supported formats are:

                - SubjectPublicKeyInfo (default)
                - PKCS1
                - OpenSSH

        Returns:
            Serialized public key as bytes object.

        Raises:
            ValueError: if the encoding or format is incorrect or unsupported.
        """
        try:
            encd = self._ENCODINGS[encoding]
            fmt = self._FORMATS[format]
        except KeyError as e:
            raise ValueError(
                f"Invalid encoding or format: {e.args[0]!r}"
            ) from e
        return self._key.public_bytes(encd, fmt)

    @classmethod
    def load(cls, data: bytes) -> RSAPublicKey:
        loader = cls._get_loader(data)
        try:
            key = loader(memoryview(data))
            if not isinstance(key, rsa.RSAPublicKey):
                raise ValueError("Key is not an RSA public key.")
        except ValueError as e:
            raise ValueError(f"Failed to load key: {e!s}") from e

        assert isinstance(key, rsa.RSAPublicKey)
        return cls(key)

    @classmethod
    def _get_loader(cls, data: bytes) -> typing.Callable:
        """
        Returns a loader function depending on the initial bytes of the key.
        """
        try:
            return cls._LOADERS[next(filter(data.startswith, cls._LOADERS))]
        except StopIteration:
            raise ValueError("Invalid format.") from None


class EncryptorContext(base.BaseEncryptorContext):
    def __init__(
        self,
        key: rsa.RSAPublicKey,
        padding: _padding.AsymmetricPadding,
    ) -> None:
        self._encrypt_func = partial(key.encrypt, padding=padding)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._encrypt_func(plaintext)


class DecryptorContext(base.BaseDecryptorContext):
    def __init__(
        self,
        key: rsa.RSAPrivateKey,
        padding: _padding.AsymmetricPadding,
    ) -> None:
        self._decrypt_func = partial(key.decrypt, padding=padding)

    def decrypt(self, ciphertext: bytes) -> bytes:
        try:
            return self._decrypt_func(ciphertext)
        except ValueError as e:
            raise exc.DecryptionError from e


class SignerContext(base.BaseSignerContext):
    def __init__(
        self,
        key: rsa.RSAPrivateKey,
        padding: _padding.AsymmetricPadding,
    ) -> None:
        self._sign_func = partial(key.sign, padding=padding)

    def sign(self, msghash: base.BaseHash) -> bytes:
        return self._sign_func(
            data=msghash.digest(),
            algorithm=utils.Prehashed(Hash._get_hash_algorithm(msghash)),
        )


class VerifierContext(base.BaseVerifierContext):
    def __init__(
        self, key: rsa.RSAPublicKey, padding: _padding.AsymmetricPadding
    ) -> None:
        self._verify_func = partial(key.verify, padding=padding)

    def verify(self, msghash: base.BaseHash, signature: bytes) -> None:
        try:
            return self._verify_func(
                signature=signature,
                data=msghash.digest(),
                algorithm=utils.Prehashed(Hash._get_hash_algorithm(msghash)),
            )
        except bkx.InvalidSignature as e:
            raise exc.SignatureError from e


def generate(bits: int, e: int = 65537) -> RSAPrivateKey:
    """
    Generate a private key with given key modulus ``bits`` and public exponent
    ``e`` (default 65537). Recommended size of ``bits`` > 1024.

    Args:
        bits: The bit length of the RSA key.
        e: The public exponent value. Default is 65537.

    Returns:
        RSAPrivateKey: The RSA private key.
    """
    return RSAPrivateKey(bits, e)


def load_public_key(data: bytes) -> RSAPublicKey:
    """Loads the public key and returns a Key interface.

    Args:
        data: The public key (a bytes-like object) to deserialize.

    Returns:
        RSAPublicKey: The RSA public key.
    """
    return RSAPublicKey.load(data)


def load_private_key(
    data: bytes,
    passphrase: bytes | None = None,
) -> RSAPrivateKey:
    """Loads the private key and returns a Key interface.

    Args:
        data: The private key (a bytes-like object) to deserialize.
        passphrase:
            The passphrase that was used to encrypt the private key. ``None``
            if the private key is not encrypted.

    Returns:
        RSAPrivateKey: The RSA private key.
    """
    return RSAPrivateKey.load(data, passphrase)
