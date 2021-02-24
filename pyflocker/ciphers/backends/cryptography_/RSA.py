from __future__ import annotations

import sys
import typing
from functools import partial

if sys.version_info >= (3, 9):
    from functools import cache as _cache
else:
    from functools import lru_cache

    def _cache(func):
        return lru_cache(maxsize=None)(func)


import cryptography.exceptions as bkx
from cryptography.hazmat.backends import default_backend as defb
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


class _RSANumbers:
    def _numbers(self):
        try:
            k = self._key.public_numbers()
        except AttributeError:
            k = self._key.private_numbers().public_numbers
        return k

    @property
    @_cache
    def e(self) -> int:
        """RSA public exponent."""
        return self._numbers().e

    @property
    @_cache
    def n(self) -> int:
        """RSA public modulus.

        The number ``n`` is such that ``n == p * q``.
        """
        return self._numbers().n


class RSAPrivateKey(_RSANumbers, base.BasePrivateKey):
    def __init__(self, n: int, e: int = 65537, **kwargs):
        if kwargs:
            self._key = kwargs.pop("key")
        else:
            self._key = rsa.generate_private_key(e, n, defb())

        # numbers
        nos = self._key.private_numbers()
        self._p = nos.p
        self._q = nos.q
        self._d = nos.d

    @property
    def p(self) -> int:
        """First factor of RSA modulus."""
        return self._p

    @property
    def q(self) -> int:
        """Second factor of RSA modulus."""
        return self._q

    @property
    def d(self) -> int:
        """The private exponent."""
        return self._d

    def public_key(self) -> RSAPublicKey:
        """Creates a public key from the private key.

        Returns:
            RSAPublicKey: The public key.
        """
        return RSAPublicKey(self._key.public_key())

    def decryptor(self, padding=OAEP()) -> _EncDecContext:
        """Creates a decryption context.

        Args:
            padding: The padding to use. Default is ``OAEP``.

        Returns:
            _EncDecContext: object for decrypting ciphertexts.
        """
        return _EncDecContext(
            True, self._key, get_padding_func(padding)(padding)
        )

    def signer(self, padding=PSS()) -> _SigVerContext:
        """Create a signer context.

        Args:
            padding: The padding to use. Default is ``PSS``.

        Returns:
            _SigVerContext: object for signing messages.
        """
        return _SigVerContext(
            True, self._key, get_padding_func(padding)(padding)
        )

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "PKCS8",
        passphrase: typing.Optional[typing.ByteString] = None,
    ) -> bytes:
        """Serialize the private key.

        Args:
            encoding (str): PEM or DER (defaults to PEM).
            format (str): The formats can be:

                - PKCS8 (default)
                - TraditionalOpenSSL
                - OpenSSH (available from pyca/cryptography version >=3.X)
                - PKCS1 (alias to TraditionalOpenSSL for Cryptodome compat)
            passphrase (bytes, bytearray, memoryview):
                A bytes-like object to protect the private key. If
                ``passphrase`` is None, the private key will be exported in the
                clear!

        Returns:
            bytes: The private key as a bytes object.

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
        data: typing.ByteString,
        passphrase: typing.Optional[typing.ByteString] = None,
    ):
        """Loads the private key as ``bytes`` object and returns
        the Key interface.

        Args:
            data (bytes, bytearray):
                The key as bytes object.
            passphrase (bytes, bytearray):
                The passphrase that deserializes the private key. ``passphrase``
                must be a ``bytes-like`` object if the key was encrypted while
                serialization, otherwise ``None``.

        Returns:
            RSAPrivateKey: RSA private key.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        fmts = {
            b"-----BEGIN OPENSSH PRIVATE KEY": ser.load_ssh_private_key,
            b"-----": ser.load_pem_private_key,
            b"0": ser.load_der_private_key,
        }

        try:
            loader = fmts[[*filter(data.startswith, fmts)][0]]
        except IndexError:
            raise ValueError("Invalid format.") from None

        # type check
        if passphrase is not None:
            passphrase = memoryview(passphrase)

        try:
            key = loader(memoryview(data), passphrase, defb())
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError("The key is not an RSA private key.")
            return cls(0, key=key)
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


class RSAPublicKey(_RSANumbers, base.BasePublicKey):
    """RSA Public Key wrapper class."""

    def __init__(self, key):
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("The key is not an RSA public key.")
        self._key = key

    def encryptor(self, padding=OAEP()) -> _EncDecContext:
        """Creates a encryption context.

        Args:
            padding: The padding to use. Defaults to OAEP.

        Returns:
            _EncDecContext: object for decrypting ciphertexts.
        """
        return _EncDecContext(
            False, self._key, get_padding_func(padding)(padding)
        )

    def verifier(self, padding=PSS()) -> _EncDecContext:
        """Creates a verifier context.

        Args:
            padding: The padding to use. Defaults to ECC.

        Returns:
            _SigVerContext: verifier object for verification.
        """
        return _SigVerContext(
            False, self._key, get_padding_func(padding)(padding)
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
            bytes: Serialized public key as bytes object.

        Raises:
            KeyError: if the encoding or format is incorrect or unsupported.
        """
        try:
            encd = ENCODINGS[encoding]
            fmt = PUBLIC_FORMATS[format]
        except KeyError as e:
            raise ValueError(f"Invalid encoding or format: {e.args}") from e
        return self._key.public_bytes(encd, fmt)

    @classmethod
    def load(cls, data: typing.ByteString) -> RSAPublicKey:
        """Loads the public key as ``bytes`` object and returns
        the Key interface.

        Args:
            data (bytes):
                The key as bytes object.

        Returns:
            RSAPublicKey: The RSA public key.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        fmts = {
            b"ssh-rsa ": ser.load_ssh_public_key,
            b"-----": ser.load_pem_public_key,
            b"0": ser.load_der_public_key,
        }

        try:
            loader = fmts[[*filter(data.startswith, fmts)][0]]
        except IndexError:
            raise ValueError("Invalid format.") from None

        try:
            return cls(loader(memoryview(data), defb()))
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. The key format might be invalid."
            ) from e


class _EncDecContext:
    def __init__(self, is_private, key, padding):
        self._is_private = is_private

        ctxname = "decrypt" if is_private else "encrypt"
        self._ctx_func = partial(getattr(key, ctxname), padding=padding)

    def encrypt(self, plaintext):
        """Encrypts the plaintext and returns the ciphertext.

        Args:
            plaintext (bytes, bytearray):
                The data to encrypt.

        Returns:
            bytes: encrypted bytes object.

        Raises:
            TypeError: If the key is a private key.
        """
        if self._is_private:
            raise TypeError("Only public keys can encrypt plaintexts.")
        return self._ctx_func(plaintext)

    def decrypt(self, ciphertext):
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
            return self._ctx_func(ciphertext)
        except ValueError as e:
            raise exc.DecryptionError from e


class _SigVerContext:
    def __init__(self, is_private, key, padding):
        self._is_private = is_private

        ctxname = "sign" if is_private else "verify"
        self._ctx_func = partial(getattr(key, ctxname), padding=padding)

    def sign(self, msghash):
        """Return the signature of the message hash.

        Args:
            msghash (:any:`BaseHash`):
                It must be a :any:`BaseHash` object, used to digest the
                message to sign.

        Returns:
            bytes: signature of the message as bytes object.

        Raises:
            TypeError: If the key is not a private key.
        """
        if not self._is_private:
            raise TypeError("Only private keys can sign messages.")
        return self._ctx_func(
            data=msghash.digest(),
            algorithm=utils.Prehashed(Hash._get_hash_algorithm(msghash)),
        )

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
            TypeError: If the key is a private key.
        """
        if self._is_private:
            raise TypeError("Only public keys can verify messages.")
        try:
            return self._ctx_func(
                signature=signature,
                data=msghash.digest(),
                algorithm=utils.Prehashed(Hash._get_hash_algorithm(msghash)),
            )
        except bkx.InvalidSignature as e:
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
