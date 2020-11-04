try:
    from Cryptodome.PublicKey import ECC
    from Cryptodome.Signature import DSS
except ModuleNotFoundError:
    from Crypto.PublicKey import ECC
    from Crypto.Signature import DSS

from .. import base, exc
from ._serialization import encodings, formats, protection_schemes
from .Hash import Hash

_sig_encodings = {
    "binary": "binary",
    "der": "der",
}

_sig_modes = {
    "fips-186-3": "fips-186-3",
    "deterministic-rfc6979": "deterministic-rfc6979",
}

curves = {k: k for k in ECC._curves}


class ECCPrivateKey(base.BasePrivateKey):
    """Represents ECC private key."""

    def __init__(self, curve=None, **kwargs):
        if kwargs:
            self._key = kwargs.pop("key")
            return
        self._key = ECC.generate(curve=curves[curve])

    def public_key(self):
        """Creates a public key from the private key

        Args:
            None

        Returns:
            :any:`ECCPublicKey`: ECCPublicKey interface.
        """
        return ECCPublicKey(self._key.public_key())

    def serialize(
        self,
        encoding="PEM",
        format="PKCS8",
        passphrase=None,
        *,
        protection=None
    ):
        """Serialize the private key.

        Args:
            encoding (str): PEM or DER (defaults to PEM).
            format (str): PKCS8 (default) or PKCS1.
            passphrase (bytes, bytearray, memoryview):
                A bytes-like object to protect the private key. If
                `passphrase` is None, the private key will be exported
                in the clear!

        Keyword Arguments:
            protection (str):
                The protection scheme to use. If password is provided
                and protection is None, 'PBKDF2WithHMAC-SHA1AndAES256-CBC'
                is used.

        Returns:
            bytes: The private key as a bytes object.

        Raises:
            ValueError:
                If the encoding is incorrect or, if DER is used with PKCS1
                or protection value is supplied with PKCS1 format.
            KeyError: if the format is invalid or not supported.
        """
        if encoding not in encodings.keys() ^ {"OpenSSH"}:
            raise TypeError("encoding must be PEM or DER")

        if format not in formats:
            raise KeyError("invalid format")

        prot = {}

        if protection is not None:
            if format == "PKCS1":
                raise TypeError("protection is meaningful only for PKCS8")
            if protection not in protection_schemes:
                raise ValueError("invalid protection scheme")
            # use a curated encryption choice and not DES-EDE3-CBC
            prot = dict(protection="PBKDF2WithHMAC-SHA1AndAES256-CBC")
        else:
            prot = dict(protection=protection)

        if passphrase is not None:
            # type checking of key
            passphrase = memoryview(passphrase).tobytes()
            # check length afterwards
            if not passphrase:
                raise ValueError("passphrase cannot be empty bytes")

        key = self._key.export_key(
            format=encodings[encoding],
            use_pkcs8=(format == "PKCS8"),
            passphrase=passphrase,
            **prot,
        )
        if isinstance(key, bytes):
            return key
        return key.encode("utf-8")

    def signer(self, *, mode="fips-186-3", encoding="binary"):
        """Create a signer context.

        Keyword Arguments:
            mode (str): The signature generation mode. It can be:

                - 'fips-186-3' (default)
                - 'deterministic-rfc6979'
            encoding (str): How the signature is encoded. It can be:

                - 'binary'
                - 'der'

        Returns:
            :any:`ECCSignerCtx`: An ECCSignerCtx object for signing messages.

        Raises:
            KeyError: if the mode or encoding is invalid or not supported.
        """
        return ECCSignerCtx(self._key, mode=mode, encoding=encoding)

    def exchange(self, peer_public_key):
        raise NotImplementedError(
            "key exchange is currently not supported by the backend."
        )

    @classmethod
    def load(cls, data, passphrase=None):
        """Loads the private key as `bytes` object and returns the Key
        interface.

        Args:
            data (bytes):
                The key as bytes object.
            password (bytes, bytearray, memoryview):
                The password that deserializes the private key.
                `password` must be a `bytes` object if the key
                was encrypted while serialization, otherwise `None`.

        Returns:
            :any:`ECCPrivateKey`:  `ECCPrivateKey` object.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        try:
            key = ECC.import_key(data, passphrase)
            if not key.has_private():
                raise ValueError("The key is not a private key")
            return cls(key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. "
                "Either Key format is invalid or "
                "password is missing or incorrect.",
            ) from e


class ECCPublicKey(base.BasePublicKey):
    """Represents ECC public key."""

    def __init__(self, key):
        self._key = key

    def serialize(self, encoding="PEM", *, compress=False):
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
            KeyError: if the encoding is not supported or invalid.
        """
        key = self._key.export_key(
            format=encodings[encoding],
            compress=compress,
        )
        if isinstance(key, bytes):
            return key
        return key.encode()

    def verifier(self, *, mode="fips-186-3", encoding="binary"):
        """Create a signer context.

        Args:
            mode: The signature generation mode. It can be:

                - 'fips-186-3' (default)
                - 'deterministic-rfc6979'
            encoding: How the signature is encoded. It can be:

                - 'binary'
                - 'der'

        Returns:
            :any:`ECCVerifierCtx`:
                A `ECCVerifierCtx` object for verifying messages.

        Raises:
            KeyError: if the mode or encoding is invalid or not supported.
        """
        return ECCVerifierCtx(self._key, mode=mode, encoding=encoding)

    @classmethod
    def load(cls, data):
        """Loads the public key as `bytes` object and returns the Key
        interface.

        Args:
            data (bytes):
                The key as bytes object.

        Returns:
            :any:`ECCPublicKey`: `ECCPublicKey` object.

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
                "Cannot deserialize key. "
                "Either Key format is invalid or "
                "password is missing or incorrect.",
            ) from e


class _SigVerContext:
    def __init__(self, key, *, mode="fips-186-3", encoding="der"):
        self._sig = DSS.new(
            key,
            mode=_sig_modes[mode],
            encoding=_sig_encodings[encoding],
        )


class ECCSignerCtx(_SigVerContext):
    """Signing context for ECC private key."""

    def sign(self, msghash):
        """Return the signature of the message hash.

        Args:
            msghash (:class:`pyflocker.ciphers.base.BaseHash`):
                `msghash` must be an instance of :any:`BaseHash`.
                Refer to :func:`pyflocker.ciphers.interfaces.Hash.new`
                function's documentation.

        Returns:
            bytes: signature of the message as bytes object.
        """
        return self._sig.sign(msghash)


class ECCVerifierCtx(_SigVerContext):
    """Verification context for ECC public key."""

    def verify(self, msghash, signature):
        """Verifies the signature of the message hash.

        Args:
            msghash (:class:`pyflocker.ciphers.base.BaseHash`):
                `msghash` must be an instance of :any:`BaseHash`.
                Refer to :func:`pyflocker.ciphers.interfaces.Hash.new`
                function's documentation.
            signature (bytes):
                signature must be a `bytes` or `bytes-like` object.

        Returns:
            None

        Raises:
            TypeError: if the `msghash` object is not from the same
                backend.
            SignatureError: if the `signature` was incorrect.
        """
        try:
            self._sig.verify(msghash, signature)
        except ValueError as e:
            raise exc.SignatureError from e
