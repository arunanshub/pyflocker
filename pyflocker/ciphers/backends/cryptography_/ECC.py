from __future__ import annotations

import typing
from types import MappingProxyType

import cryptography.exceptions as bkx
from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    utils,
    x448,
    x25519,
)

from ... import base, exc
from . import Hash
from .asymmetric import ENCODINGS, PRIVATE_FORMATS, PUBLIC_FORMATS

# divide curves (ie. public and private keys) into categories
EXCHANGE_CURVES = MappingProxyType(
    {
        "x448": x448.X448PrivateKey,
        "x25519": x25519.X25519PrivateKey,
    }
)

EXCHANGE_CURVES_PUBLIC = MappingProxyType(
    {
        "x448": x448.X448PublicKey,
        "x25519": x25519.X25519PublicKey,
    }
)

EDWARDS_CURVES = MappingProxyType(
    {
        "ed448": ed448.Ed448PrivateKey,
        "ed25519": ed25519.Ed25519PrivateKey,
    }
)

EDWARDS_CURVES_PUBLIC = MappingProxyType(
    {
        "ed448": ed448.Ed448PublicKey,
        "ed25519": ed25519.Ed25519PublicKey,
    }
)

SPECIAL_CURVES = MappingProxyType(
    {
        **EXCHANGE_CURVES,
        **EDWARDS_CURVES,
    }
)

SPECIAL_CURVES_PUBLIC = MappingProxyType(
    {
        **EDWARDS_CURVES_PUBLIC,
        **EXCHANGE_CURVES_PUBLIC,
    }
)

CURVES = MappingProxyType(
    {
        "secp256r1": ec.SECP256R1,
        "secp384r1": ec.SECP384R1,
        "secp521r1": ec.SECP521R1,
        "secp224r1": ec.SECP224R1,
        "secp192r1": ec.SECP192R1,
        "secp256k1": ec.SECP256K1,
        # aliases for PyCryptodome
        # note that only those CURVES are aliased which are
        # currently supported by the same.
        "NIST P-256": ec.SECP256R1,
        "p256": ec.SECP256R1,
        "P-256": ec.SECP256R1,
        "prime256v1": ec.SECP256R1,
        "NIST P-384": ec.SECP384R1,
        "p384": ec.SECP384R1,
        "P-384": ec.SECP384R1,
        "prime384v1": ec.SECP384R1,
        "NIST P-521": ec.SECP521R1,
        "p521": ec.SECP521R1,
        "P-521": ec.SECP521R1,
        "prime521v1": ec.SECP521R1,
        **SPECIAL_CURVES,
    }
)

EXCHANGE_ALGORITHMS = MappingProxyType(
    {
        "ECDH": ec.ECDH,
    }
)

SIGNATURE_ALGORITHMS = MappingProxyType(
    {
        "ECDSA": ec.ECDSA,
    }
)

del MappingProxyType


class ECCPrivateKey(base.BasePrivateKey):
    """Represents ECC private key."""

    def __init__(self, curve: str, **kwargs):
        if kwargs:
            self._key = kwargs.pop("key")
            return
        try:
            if curve not in SPECIAL_CURVES:
                self._key = ec.generate_private_key(CURVES[curve], defb())
                return
            self._key = SPECIAL_CURVES[curve].generate()
        except KeyError as e:
            raise ValueError(f"Invalid curve: {curve}") from e

    def public_key(self) -> ECCPublicKey:
        """Creates a public key from the private key.

        Returns:
            ECCPublicKey: The public key.
        """
        return ECCPublicKey(self._key.public_key())

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "PKCS8",
        passphrase: typing.Optional[typing.ByteString] = None,
    ):
        """Serialize the private key.

        Args:
            encoding (str):
                The supported encodings are:

                - PEM (default)
                - DER
                - Raw

                Raw encoding can be used only with Ed* and X* keys.
            format (str):
                The supported formats are:

                - PKCS8 (default)
                - TraditionalOpenSSL
                - OpenSSH (available from pyca/cryptography version >=3.X)
                - PKCS1 (alias to TraditionalOpenSSL for Cryptodome compat)
                - Raw (can only be used with Raw encoding and Ed*/X* keys)
            passphrase (bytes, bytearray, memoryview):
                A bytes-like object to protect the private key.
                If ``passphrase`` is None, the private key will be exported
                in the clear!

        Note:
            ``passphrase`` cannot be used with ``Raw`` encoding.

        Returns:
            bytes: The private key as a bytes object.

        Raises:
           ValueError: if the format or encoding is invalid or not supported.
           TypeError: if the passphrase is not a ``bytes-like`` object.
        """
        try:
            encoding_ = ENCODINGS[encoding]
            format_ = PRIVATE_FORMATS[format]
        except KeyError as e:
            raise ValueError("The encoding or format is invalid.") from e

        if passphrase is None:
            protection = ser.NoEncryption()
        else:
            if not isinstance(passphrase, (bytes, bytearray, memoryview)):
                raise TypeError("passphrase must be a bytes-like object.")
            protection = ser.BestAvailableEncryption(passphrase)
        return self._key.private_bytes(encoding_, format_, protection)

    def exchange(
        self,
        peer_public_key: typing.ByteString,
        algorithm: str = "ECDH",
    ):
        """Perform a key exchange.

        Args:
            peer_public_key (bytes-like, :any:`ECCPublicKey`):
                The public key from the other party. It must be a serialized
                :any:`ECCPublicKey` object.
            algorithm (str):
                The algorithm to use to perform the exchange.
                Only ECDH is avaliable. Ignored for X* keys.

        Returns:
            bytes: Shared key as bytes object.

        Raises:
            NotImplementedError: the key does not support key exchange.
        """
        # Ed* key
        if isinstance(self._key, (*EDWARDS_CURVES.values(),)):
            raise NotImplementedError(
                "Edwards curves don't suport key exchange."
            )

        if not isinstance(peer_public_key, (bytes, bytearray, memoryview)):
            raise TypeError("peer_public_key must be a bytes-like object.")

        peer_public_key = ECCPublicKey.load(peer_public_key)

        # X* key
        if isinstance(self._key, (*EXCHANGE_CURVES.values(),)):
            return self._key.exchange(peer_public_key._key)

        # any other key
        return self._key.exchange(
            EXCHANGE_ALGORITHMS[algorithm](),
            peer_public_key._key,
        )

    def signer(self, algorithm: str = "ECDSA"):
        """Create a signer context.

        Args:
            algorithm (str):
                The algorithm to use for signing. Currently ECDSA is only
                available.
                Ignored from Ed* keys.

        Returns:
            _SigVerContext: A signer object.

        Raises:
            NotImplementedError: if the key doesn't support signing.
        """
        # special case 1: x* key
        if isinstance(self._key, (*EXCHANGE_CURVES.values(),)):
            raise NotImplementedError(
                "Exchange only curves don't support signing."
            )
        # special case 2: ed* key
        if isinstance(self._key, (*EDWARDS_CURVES.values(),)):
            return _SigVerContext(True, self._key, None)
        return _SigVerContext(True, self._key, SIGNATURE_ALGORITHMS[algorithm])

    @classmethod
    def load(
        cls,
        data: typing.ByteString,
        passphrase: typing.Optional[typing.ByteString] = None,
        *,
        edwards: bool = True,
    ):
        """Loads the private key as `bytes` object and returns a key object.

        Args:
            data (bytes, bytearray):
                The key as a ``bytes-like`` object.
            passphrase (bytes, bytearray, memoryview, None):
                The passphrase that deserializes the private key.
                ``passphrase`` must be a ``bytes-like`` object if the key
                was encrypted while serialization, otherwise ``None``.

        Keyword Arguments:
            edwards (bool):
                Whether the ``Raw`` encoded key of length 32 bytes
                must be imported as an ``Ed25519`` key or ``X25519`` key.

                If ``True``, the key will be imported as an ``Ed25519`` key,
                otherwise an ``X25519`` key.

                This argument is ignored for all other serialized key types.

        Returns:
            ECCPrivateKey: A private key.

        Raises:
            ValueError: if the key could not be deserialized.
            TypeError: if passphrase is not a bytes object.
        """
        # type check
        if passphrase is not None:
            if not isinstance(passphrase, (bytes, bytearray, memoryview)):
                raise TypeError("passphrase must be a bytes object.")

        fmts = {
            b"-----BEGIN OPENSSH PRIVATE KEY": ser.load_ssh_private_key,
            b"-----": ser.load_pem_private_key,
            b"0": ser.load_der_private_key,
        }

        try:
            loader = fmts[[*filter(data.startswith, fmts)][0]]
        except IndexError:
            loader = cls._get_raw_ecc_loader(data, edwards)

        # type check
        if passphrase is not None:
            if not isinstance(passphrase, (bytes, bytearray, memoryview)):
                raise TypeError("passphrase must be a bytes-like object.")

        try:
            key = loader(memoryview(data), passphrase, defb())
            if not isinstance(
                key, (ec.EllipticCurvePrivateKey, *SPECIAL_CURVES.values())
            ):
                raise ValueError("The key is not an EC private key.")
            return cls(None, key=key)
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

    @staticmethod
    def _get_raw_ecc_loader(data, edwards=True):
        fmts = {
            57: SPECIAL_CURVES["ed448"].from_private_bytes,
            56: SPECIAL_CURVES["x448"].from_private_bytes,
            32: None,
        }

        try:
            loader = fmts[len(data)]
        except IndexError as e:
            raise ValueError("Invalid format.") from e

        if loader is None:
            if edwards:
                loader = SPECIAL_CURVES["ed25519"].from_private_bytes
            else:
                loader = SPECIAL_CURVES["x25519"].from_private_bytes

        return lambda data, *args: loader(data)


class ECCPublicKey(base.BasePublicKey):
    """Represents ECC public key."""

    def __init__(self, key):
        if not isinstance(
            key,
            (
                ec.EllipticCurvePublicKey,
                *SPECIAL_CURVES_PUBLIC.values(),
            ),
        ):
            raise ValueError("The key is not an EC public key.")
        self._key = key

    def verifier(self, algorithm: str = "ECDSA"):
        """Create a verifier context.

        Args:
            algorithm (str): The algorithm to use for verification.
                Currently ECDSA is only available.

        Returns:
            _SigVerContext: A verifier object.

        Raises:
            NotImplementedError: if the key doesn't support verification.
        """
        # Special case 1: x* only key
        if isinstance(self._key, (*EXCHANGE_CURVES_PUBLIC.values(),)):
            raise NotImplementedError(
                "Exchange only curves don't support verification."
            )

        # Special case 2: ed* only key
        if isinstance(self._key, (*EDWARDS_CURVES_PUBLIC.values(),)):
            return _SigVerContext(False, self._key, None)
        return _SigVerContext(
            False, self._key, SIGNATURE_ALGORITHMS[algorithm]
        )

    def serialize(
        self, encoding: str = "PEM", format: str = "SubjectPublicKeyInfo"
    ):
        """Serialize the public key.

        Args:
            encoding (str):
                The supported encoding formats are:

                - PEM (default)
                - DER
                - OpenSSH
                - Raw
                - X962

                Raw can be used only with Ed* and X* keys.
            format (str):
                The supported formats are:

                - SubjectPublicKeyInfo (default)
                - PKCS1
                - OpenSSH
                - ComperssedPoint (X962 encoding only)
                - UncompressedPoint (X962 encoding only)
                - Raw (Raw encoding only; only with Ed*/X* keys)

        Returns:
            bytes: Serialized public key as bytes object.

        Raises:
            ValueError: if the encoding or format is incorrect or unsupported.
        """
        try:
            encoding_ = ENCODINGS[encoding]
            format_ = PUBLIC_FORMATS[format]
        except KeyError as e:
            raise ValueError("The encoding or format is invalid.") from e
        return self._key.public_bytes(encoding_, format_)

    @classmethod
    def load(cls, data: typing.ByteString, *, edwards: bool = True):
        """Loads the public key as ``bytes`` object and returns
        the Key interface.

        Args:
            data (bytes, bytearray):
                The key as bytes object.

        Keyword Arguments:
            edwards (bool):
                Whether the ``Raw`` encoded key of length 32 bytes
                must be imported as an ``Ed25519`` key or ``X25519`` key.

                If ``True``, the key will be imported as an ``Ed25519`` key,
                otherwise an ``X25519`` key.

                This argument is ignored for all other serialized key types.

        Returns:
            ECCPublicKey: The ECC public key.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        fmts = {
            b"ecdsa-": ser.load_ssh_public_key,
            b"-----": ser.load_pem_public_key,
            b"0": ser.load_der_public_key,
        }

        try:
            loader = fmts[[*filter(data.startswith, fmts)][0]]
        except IndexError:
            loader = cls._get_raw_ecc_loader(data, edwards)

        try:
            key = loader(memoryview(data), defb())
            return cls(key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Incorrect key format.",
            ) from e

    @staticmethod
    def _get_raw_ecc_loader(data, edwards=True):
        fmts = {
            57: SPECIAL_CURVES_PUBLIC["ed448"].from_public_bytes,
            56: SPECIAL_CURVES_PUBLIC["x448"].from_public_bytes,
            32: None,
        }

        try:
            loader = fmts[len(data)]
        except IndexError as e:
            raise ValueError("Invalid format.") from e

        if loader is None:
            if edwards:
                loader = SPECIAL_CURVES["ed25519"].from_public_bytes
            else:
                loader = SPECIAL_CURVES["x25519"].from_public_bytes

        return lambda data, *args: loader(data)


class _SigVerContext:
    def __init__(self, is_private, key, algorithm):
        self._is_private = is_private
        self._ctx_func = key.sign if is_private else key.verify
        self._algorithm = algorithm

    def sign(self, msghash: base.BaseHash):
        """Return the signature of the message hash.

        Args:
            msghash (:class:`pyflocker.ciphers.base.BaseHash`):
                The hash algorithm used to digest the object.

        Returns:
            bytes: signature of the message as bytes object.

        Raises:
            TypeError: if the key is not a private key.
        """
        if not self._is_private:
            raise TypeError("Only private keys can sign messages.")

        if self._algorithm is None:
            return self._ctx_func(msghash.digest())
        return self._ctx_func(
            msghash.digest(),
            self._algorithm(
                utils.Prehashed(Hash._get_hash_algorithm(msghash))
            ),
        )

    def verify(self, msghash: base.BaseHash, signature: typing.ByteString):
        """Verifies the signature of the message hash.

        Args:
            msghash (:class:`pyflocker.ciphers.base.BaseHash`):
                The hash algorithm used to digest the object.

            signature (bytes, bytesarray):
                signature must be a ``bytes`` or ``bytes-like`` object.

        Returns:
            None

        Raises:
            SignatureError: if the signature was incorrect.
            TypeError: if the key is not a public key.
        """
        if self._is_private:
            raise TypeError("Only public keys can verify messages.")

        try:
            if self._algorithm is None:
                return self._ctx_func(signature, msghash.digest())
            return self._ctx_func(
                signature,
                msghash.digest(),
                self._algorithm(
                    utils.Prehashed(Hash._get_hash_algorithm(msghash))
                ),
            )
        except bkx.InvalidSignature as e:
            raise exc.SignatureError from e


def generate(curve: str) -> ECCPrivateKey:
    """
    Generate a private key with given curve ``curve``.

    Args:
        curve (str): The name of the curve to use.

    Returns:
        ECCPrivateKey: An ECC private key.

    Raises:
        ValueError: if the curve the name of the curve is invalid.
    """
    return ECCPrivateKey(curve)


def load_public_key(data: typing.ByteString, *, edwards: bool = True):
    """Loads the public key and returns a Key interface.

    Args:
        data (bytes, bytearray):
            The public key (a bytes-like object) to deserialize.

    Keyword Arguments:
        edwards (bool, NoneType):
            Whether the ``Raw`` encoded key of length 32 bytes
            must be imported as an ``Ed25519`` key or ``X25519`` key.

            If ``True``, the key will be imported as an ``Ed25519`` key,
            otherwise an ``X25519`` key.

            This argument is ignored for all other serialized key types.

    Returns:
        ECCPublicKey: An ECC public key.
    """
    return ECCPublicKey.load(data, edwards=edwards)


def load_private_key(
    data: typing.ByteString,
    passphrase: typing.Optional[typing.ByteString] = None,
    *,
    edwards: bool = True,
) -> ECCPrivateKey:
    """Loads the private key and returns a Key interface.

    If the private key was not encrypted duting the serialization,
    ``passphrase`` must be ``None``, otherwise it must be a ``bytes-like``
    object.

    Args:
        data (bytes, bytearray):
            The private key (a bytes-like object) to deserialize.
        passphrase (bytes, bytearray):
            The passphrase (in bytes) that was used to encrypt the
            private key. `None` if the key was not encrypted.

    Keyword Arguments:
        edwards (bool, NoneType):
            Whether the ``Raw`` encoded key of length 32 bytes
            must be imported as an ``Ed25519`` key or ``X25519`` key.

            If ``True``, the key will be imported as an ``Ed25519`` key,
            otherwise an ``X25519`` key.

            This argument is ignored for all other serialized key types.

    Returns:
        ECCPrivateKey: An ECC private key.
    """
    return ECCPrivateKey.load(
        data,
        passphrase,
        edwards=edwards,
    )
