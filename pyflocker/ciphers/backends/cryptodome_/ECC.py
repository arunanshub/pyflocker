from __future__ import annotations

import typing

from Cryptodome.PublicKey import ECC

from ... import base, exc
from .asymmetric import ENCODINGS, FORMATS, PROTECTION_SCHEMES, get_DSS

CURVES = {k: k for k in ECC._curves}


class ECCPrivateKey(base.BasePrivateKey):
    """ECC private key."""

    def __init__(self, curve: str, **kwargs):
        if kwargs:
            self._key = kwargs.pop("key")
            return
        try:
            self._key = ECC.generate(curve=CURVES[curve])
        except KeyError as e:
            raise ValueError(f"Invalid curve: {curve}") from e

    def public_key(self) -> ECCPublicKey:
        """Creates a public key from the private key

        Returns:
            ECCPublicKey: A public key.
        """
        return ECCPublicKey(self._key.public_key())

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "PKCS8",
        passphrase: typing.Optional[typing.ByteString] = None,
        *,
        protection: typing.Optional[str] = None,
    ) -> bytes:
        """Serialize the private key.

        Args:
            encoding (str): PEM or DER (defaults to PEM).
            format (str): PKCS8 (default) or PKCS1.
            passphrase (bytes, bytearray, memoryview):
                A bytes-like object to protect the private key. If
                ``passphrase`` is None, the private key will be exported
                in the clear!

        Keyword Arguments:
            protection (str):
                The protection scheme to use. If passphrase is provided
                and protection is None, ``PBKDF2WithHMAC-SHA1AndAES256-CBC``
                is used.

        Returns:
            bytes: The private key as a bytes object.

        Raises:
            ValueError:
                If the encoding is incorrect or,
                if DER is used with PKCS1 or,
                protection value is supplied with PKCS1 format or,
                passphrase is empty when protection value is supplied.
            KeyError: if the format is invalid or not supported.
            TypeError:
                if the passphrase is not a bytes-like object when protection
                is supplied.
        """
        if encoding not in ENCODINGS.keys() ^ {"OpenSSH"}:
            raise TypeError("encoding must be PEM or DER")

        if format not in FORMATS:
            raise ValueError("invalid format")

        if protection is not None:
            if format == "PKCS1":
                raise TypeError("protection is meaningful only for PKCS8")
            if protection not in PROTECTION_SCHEMES:
                raise ValueError("invalid protection scheme")
            # use a curated encryption choice and not DES-EDE3-CBC
            prot = dict(protection="PBKDF2WithHMAC-SHA1AndAES256-CBC")
        else:
            prot = dict(protection=protection)

        if passphrase is not None:
            # type checking of key
            if not isinstance(passphrase, (bytes, bytearray, memoryview)):
                raise TypeError("passphrase must be a bytes-like object.")
            # check length afterwards
            if not passphrase:
                raise ValueError("passphrase cannot be empty bytes")

        try:
            key = self._key.export_key(
                format=ENCODINGS[encoding],
                use_pkcs8=(format == "PKCS8"),
                passphrase=passphrase,
                **prot,
            )
        except KeyError as e:
            raise ValueError(f"Invalid encoding: {e.args}") from e

        if isinstance(key, bytes):
            return key
        return key.encode("utf-8")

    def signer(self, *, mode: str = "fips-186-3", encoding: str = "binary"):
        """Create a signer context.

        Keyword Arguments:
            mode (str):
                The signature generation mode. It can be:

                - "fips-186-3" (default)
                - "deterministic-rfc6979"
            encoding (str):
                How the signature is encoded. It can be:

                - "binary"
                - "der"

        Returns:
            _SigVerContext: An object for signing messages.

        Raises:
            ValueError: if the mode or encoding is invalid or not supported.
        """
        return _SigVerContext(True, get_DSS(self._key, mode, encoding))

    def exchange(self, peer_public_key: typing.ByteString) -> bytes:
        raise NotImplementedError(
            "key exchange is currently not supported by the backend."
        )

    @classmethod
    def load(
        cls,
        data: typing.ByteString,
        passphrase: typing.Optional[typing.ByteString] = None,
    ):
        """Loads the private key as binary object and returns the Key
        interface.

        Args:
            data (bytes):
                The key as bytes object.
            passphrase (bytes, bytearray, memoryview):
                The passphrase that deserializes the private key.
                ``passphrase`` must be a ``bytes`` object if the key
                was encrypted while serialization, otherwise ``None``.

        Returns:
            ECCPrivateKey: An ECC private key.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        try:
            key = ECC.import_key(data, passphrase)
            if not key.has_private():
                raise ValueError("The key is not a private key")
            return cls(None, key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Either Key format is invalid "
                "or passphrase is missing or incorrect."
            ) from e


class ECCPublicKey(base.BasePublicKey):
    """Represents ECC public key."""

    def __init__(self, key):
        self._key = key

    def serialize(self, encoding: str = "PEM", *, compress: bool = False):
        """Serialize the private key.

        Args:
            encoding (str): PEM or DER.

        Keyword Arguments:
            compress (bool):
                Whether to export the public key with a more compact
                representation with only the x-coordinate. Default is
                False.

        Returns:
            bytes: The serialized public key as bytes object.

        Raises:
            ValueError: if the encoding is not supported or invalid.
        """
        try:
            key = self._key.export_key(
                format=ENCODINGS[encoding],
                compress=compress,
            )
        except KeyError as e:
            raise ValueError(f"Invalid encoding: {e.args}") from e
        if isinstance(key, bytes):
            return key
        return key.encode()

    def verifier(self, *, mode: str = "fips-186-3", encoding: str = "binary"):
        """Create a DSS verifier context.

        Args:
            mode:
                The signature generation mode. It can be:

                - "fips-186-3" (default)
                - "deterministic-rfc6979"
            encoding:
                How the signature is encoded. It can be:

                - "binary"
                - "der"

        Returns:
            _SigVerContext: A verifier object.

        Raises:
            ValueError: if the mode or encoding is invalid or not supported.
        """
        return _SigVerContext(False, get_DSS(self._key, mode, encoding))

    @classmethod
    def load(cls, data: typing.ByteString):
        """Loads the public key as binary object and returns the Key object.

        Args:
            data (bytes, bytearray):
                The key as bytes object.

        Returns:
            ECCPublicKey: An ECC public key.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        try:
            key = ECC.import_key(data)
            if key.has_private():
                raise ValueError("The key is not a private key")
            return cls(key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Either Key format is invalid or "
                "passphrase is missing or incorrect."
            ) from e


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

        Raises:
            TypeError: if the key is a public key.
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
            signature (bytes, bytearray):
                signature must be a ``bytes`` or ``bytes-like`` object.

        Returns:
            None

        Raises:
            TypeError: if the key is a private key.
            SignatureError: if the signature was incorrect.
        """
        if self._is_private:
            raise TypeError("Only public keys can verify messages.")
        try:
            self._ctx.verify(msghash, signature)
        except ValueError as e:
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


def load_public_key(data: typing.ByteString):
    """Loads the public key and returns a Key interface.

    Args:
        data (bytes, bytearray):
            The public key (a bytes-like object) to deserialize.

    Returns:
        ECCPublicKey: An ECC public key.
    """
    return ECCPublicKey.load(data)


def load_private_key(
    data: typing.ByteString,
    passphrase: typing.Optional[typing.ByteString] = None,
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

    Returns:
        ECCPrivateKey: An ECC private key.
    """
    return ECCPrivateKey.load(data, passphrase)
