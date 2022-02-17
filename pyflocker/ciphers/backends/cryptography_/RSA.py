from __future__ import annotations

import typing
from functools import partial

import cryptography.exceptions as bkx
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import rsa, utils

from ... import base, exc
from ..asymmetric import OAEP, PSS
from . import Hash
from .asymmetric import (
    ENCODINGS,
    PRIVATE_FORMATS,
    PUBLIC_FORMATS,
    get_padding_func,
)

_supported_encodings = frozenset(
    (
        "PEM",
        "DER",
        "OpenSSH",
    )
)


class RSAPrivateKey(base.BaseRSAPrivateKey):
    def __init__(self, n: int, e: int = 65537, **kwargs):
        if kwargs:
            self._key = kwargs.pop("key")
        else:
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

    def decryptor(self, padding=OAEP()) -> DecryptorContext:
        return DecryptorContext(
            self._key,
            get_padding_func(padding)(padding),
        )

    def signer(self, padding=PSS()) -> SignerContext:
        return SignerContext(
            self._key,
            get_padding_func(padding)(padding),
        )

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "PKCS8",
        passphrase: typing.Optional[bytes] = None,
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
        if encoding not in _supported_encodings ^ {"OpenSSH"}:
            raise ValueError("Encoding must be PEM or DER")

        try:
            encd = ENCODINGS[encoding]
            fmt = PRIVATE_FORMATS[format]
        except KeyError as e:
            raise ValueError("The encoding or format is invalid.") from e

        prot: ser.KeySerializationEncryption
        if passphrase is None:
            prot = ser.NoEncryption()
        else:
            prot = ser.BestAvailableEncryption(
                memoryview(passphrase).tobytes()
            )
        return self._key.private_bytes(encd, fmt, prot)

    @classmethod
    def load(
        cls,
        data: bytes,
        passphrase: typing.Optional[bytes] = None,
    ) -> RSAPrivateKey:
        formats = {
            b"-----BEGIN OPENSSH PRIVATE KEY": ser.load_ssh_private_key,
            b"-----": ser.load_pem_private_key,
            b"0": ser.load_der_private_key,
        }

        try:
            loader = formats[next(filter(data.startswith, formats))]
        except StopIteration:
            raise ValueError("Invalid format.") from None

        # type check
        if passphrase is not None:
            passphrase = memoryview(passphrase).tobytes()

        try:
            key = loader(memoryview(data), passphrase)
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError("The key is not an RSA private key.")
            return cls(1024, key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Either Key format is invalid or "
                "passphrase is incorrect."
            ) from e
        except TypeError as e:
            raise ValueError(
                "The key is encrypted but the passphrase is not given or the"
                " key is not encrypted but the passphrase is given."
                " Cannot deserialize the key."
            ) from e


class RSAPublicKey(base.BaseRSAPublicKey):
    """RSA Public Key wrapper class."""

    def __init__(self, key):
        if not isinstance(key, rsa.RSAPublicKey):
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

    def encryptor(self, padding=OAEP()) -> EncryptorContext:
        return EncryptorContext(
            self._key,
            get_padding_func(padding)(padding),
        )

    def verifier(self, padding=PSS()) -> VerifierContext:
        return VerifierContext(
            self._key,
            get_padding_func(padding)(padding),
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
            encd = ENCODINGS[encoding]
            fmt = PUBLIC_FORMATS[format]
        except KeyError as e:
            raise ValueError(f"Invalid encoding or format: {encoding}") from e
        return self._key.public_bytes(encd, fmt)

    @classmethod
    def load(cls, data: bytes) -> RSAPublicKey:
        formats = {
            b"ssh-rsa ": ser.load_ssh_public_key,
            b"-----": ser.load_pem_public_key,
            b"0": ser.load_der_public_key,
        }

        try:
            loader = formats[next(filter(data.startswith, formats))]
        except StopIteration:
            raise ValueError("Invalid format.") from None

        try:
            return cls(loader(memoryview(data)))
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. The key format might be invalid."
            ) from e


class EncryptorContext(base.BaseEncryptorContext):
    def __init__(self, key, padding):
        self._encrypt_func = partial(getattr(key, "encrypt"), padding=padding)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._encrypt_func(plaintext)


class DecryptorContext(base.BaseDecryptorContext):
    def __init__(self, key, padding):
        self._decrypt_func = partial(getattr(key, "decrypt"), padding=padding)

    def decrypt(self, ciphertext: bytes) -> bytes:
        try:
            return self._decrypt_func(ciphertext)
        except ValueError as e:
            raise exc.DecryptionError from e


class SignerContext(base.BaseSignerContext):
    def __init__(self, key, padding):
        self._sign_func = partial(getattr(key, "sign"), padding=padding)

    def sign(self, msghash: base.BaseHash) -> bytes:
        return self._sign_func(
            data=msghash.digest(),
            algorithm=utils.Prehashed(Hash._get_hash_algorithm(msghash)),
        )


class VerifierContext(base.BaseVerifierContext):
    def __init__(self, key, padding):
        self._verify_func = partial(getattr(key, "verify"), padding=padding)

    def verify(self, msghash: base.BaseHash, signature: bytes):
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
    passphrase: typing.Optional[bytes] = None,
) -> RSAPrivateKey:
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    ``passphrase`` must be ``None``, otherwise it must be a ``bytes`` object.

    Args:
        data: The private key (a bytes-like object) to deserialize.
        passphrase:
            The passphrase that was used to encrypt the private key. ``None``
            if the private key is not encrypted.

    Returns:
        RSAPrivateKey: The RSA private key.
    """
    return RSAPrivateKey.load(data, passphrase)
