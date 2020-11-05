from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric import (
    x448,
    x25519,
    ed448,
    ed25519,
)
import cryptography.exceptions as bkx

from .Hash import Hash
from .. import base, exc
from ._serialization import encodings, private_format, public_format

curves = {
    "secp256r1": ec.SECP256R1,
    "secp384r1": ec.SECP384R1,
    "secp521r1": ec.SECP521R1,
    "secp224r1": ec.SECP224R1,
    "secp192r1": ec.SECP192R1,
    "secp256k1": ec.SECP256K1,
    # aliases for PyCryptodome
    # note that only those curves are aliased which are
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
}

# some special cases which require extra handling...
special_curves = {
    "x448": x448.X448PrivateKey,
    "x25519": x25519.X25519PrivateKey,
    "ed448": ed448.Ed448PrivateKey,
    "ed25519": ed25519.Ed25519PrivateKey,
}

# ...but they are still curves
curves.update(special_curves)

exchange_algorithms = {
    "ECDH": ec.ECDH,
}

signature_algorithms = {
    "ECDSA": ec.ECDSA,
}


class ECCPrivateKey(base.BasePrivateKey):
    """Represents ECC private key."""

    def __init__(self, curve=None, **kwargs):
        if kwargs:
            key = kwargs.pop("key")
            if not isinstance(
                key,
                (
                    ec.EllipticCurvePrivateKey,
                    *special_curves.values(),
                ),
            ):
                raise ValueError("The key is not an EC private key.")
            self._key = key
        else:
            if curve not in special_curves:
                self._key = ec.generate_private_key(
                    curves[curve],
                    defb(),
                )
            else:
                self._key = curves[curve].generate()

    def public_key(self):
        """Creates a public key from the private key

        Returns:
            :any:`ECCPublicKey`: ECCPublicKey interface.
        """
        return ECCPublicKey(self._key.public_key())

    def serialize(self, encoding="PEM", format="PKCS8", passphrase=None):
        """Serialize the private key.

        Args:
            encoding (str): PEM, DER or Raw (defaults to PEM).
                Raw encoding can be used only with Ed* and X* keys.
            format (str): The formats can be:

              - PKCS8 (default)
              - TraditionalOpenSSL
              - OpenSSH (available from pyca/cryptography version >=3.X)
              - PKCS1 (alias to TraditionalOpenSSL for Cryptodome compat)
              - Raw (can only be used with Raw encoding and Ed*/X* keys)
            passphrase (bytes, bytearray, memoryview):
                A bytes-like object to protect the private key.
                If `passphrase` is None, the private key will be exported
                in the clear!

        Note:
            `passphrase` cannot be used with `Raw` encoding.

        Returns:
            bytes: The private key as a bytes object.

        Raises:
           KeyError:
                if the format or encoding is invalid or not supported.
        """
        encd = encodings[encoding]
        fmt = private_format[format]
        if passphrase is None:
            prot = ser.NoEncryption()
        else:
            prot = ser.BestAvailableEncryption(
                memoryview(passphrase).tobytes()
            )
        return self._key.private_bytes(encd, fmt, prot)

    def exchange(self, peer_public_key, algorithm="ECDH"):
        """Perform a key exchange.

        Args:
            peer_public_key (bytes, :any:`ECCPublicKey`):
                The public key from the other party.
                It can be a :any:`ECCPublicKey` object or a serialized
                :any:`ECCPublicKey` in `bytes`.
            algorithm (str):
                The algorithm to use to perform the exchange.
                Only ECDH is avaliable.

        Returns:
            bytes: Shared key as bytes object.

        Raises:
            NotImplementedError: the key does not support key exchange.
        """
        if not hasattr(self._key, "exchange"):
            raise NotImplementedError

        if isinstance(peer_public_key, (bytes, bytearray, memoryview)):
            peer_public_key = ECCPublicKey.load(peer_public_key)

        if not hasattr(self._key, "sign"):
            return self._key.exchange(peer_public_key._key)

        return self._key.exchange(
            exchange_algorithms[algorithm](),
            peer_public_key._key,
        )

    def signer(self, algorithm="ECDSA"):
        """Create a signer context.

        Args:
            algorithm (str): The algorithm to use for signing.
                Currently ECDSA is only available.

        Returns:
            :any:`ECCSignerCtx`:
                An ECCSignerCtx object for signing messages.

        Raises:
            NotImplementedError: if the key doesn't support signing.
        """
        # special case 1: x* key
        if not hasattr(self._key, "sign"):
            raise NotImplementedError
        # special case 2: ed* key
        if not hasattr(self._key, "exchange"):
            return ECCSignerCtx(self._key, None)

        return ECCSignerCtx(self._key, signature_algorithms[algorithm])

    @classmethod
    def load(cls, data, password=None, *, edwards=None):
        """Loads the private key as `bytes` object and returns
        the Key interface.

        Args:
            data (bytes, bytearray):
                The key as bytes object.
            password (bytes, bytearray):
                The password that deserializes the private key.
                `password` must be a `bytes` object if the key
                was encrypted while serialization, otherwise `None`.

        Keyword Arguments:
            edwards (bool, NoneType):
                Whether the `Raw` encoded key of length 32 bytes
                must be imported as an `Ed25519` key or `X25519` key.

                If `True`, the key will be imported as an `Ed25519` key,
                otherwise an `X25519` key.

        Returns:
            :any:`ECCPrivateKey`: ECCPrivateKey interface object.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        if data.startswith(b"-----BEGIN OPENSSH PRIVATE KEY"):
            loader = ser.load_ssh_private_key

        elif data.startswith(b"-----"):
            loader = ser.load_pem_private_key

        elif data[0] == 0x30:
            loader = ser.load_der_private_key

        elif len(data) == 57:
            loader = lambda data, *args: (
                ed448.Ed448PrivateKey.from_private_bytes(data)
            )

        elif len(data) == 56:
            loader = lambda data, *args: (
                x448.X448PrivateKey.from_private_bytes(data)
            )

        elif len(data) == 32:
            if edwards:
                loader = lambda data, *args: (
                    ed25519.Ed25519PrivateKey.from_private_bytes(data)
                )
            else:
                loader = lambda data, *args: (
                    x25519.X25519PrivateKey.from_private_bytes(data)
                )

        else:
            raise ValueError("incorrect key format")

        # type check
        if password is not None:
            password = memoryview(password)

        try:
            key = loader(
                memoryview(data),
                password,
                defb(),
            )
            return cls(key=key)
        except (ValueError, TypeError) as e:
            raise ValueError(
                "Cannot deserialize key. "
                "Either Key format is invalid or "
                "password is missing or incorrect.",
            ) from e


class ECCPublicKey(base.BasePublicKey):
    """Represents ECC public key."""

    def __init__(self, key):
        if not isinstance(
            key,
            (
                ec.EllipticCurvePublicKey,
                x448.X448PublicKey,
                x25519.X25519PublicKey,
                ed25519.Ed25519PublicKey,
                ed448.Ed448PublicKey,
            ),
        ):
            raise ValueError("The key is not an EC public key.")
        self._key = key

    def verifier(self, algorithm="ECDSA"):
        """Create a verifier context.

        Args:
            algorithm: The algorithm to use for verification.
                Currently ECDSA is only available.

        Returns:
            :any:`ECCVerifierCtx`:
                An `ECCVerifierCtx` object for verifying messages.

        Raises:
            NotImplementedError: if the key doesn't support verification.
        """
        # Special case 1: x* only key
        if not hasattr(self._key, "verify"):
            raise NotImplementedError

        # Special case 2: ed* only key
        if not hasattr(self._key, "curve"):
            return ECCVerifierCtx(self._key, None)
        return ECCVerifierCtx(self._key, signature_algorithms[algorithm])

    def serialize(self, encoding="PEM", format="SubjectPublicKeyInfo"):
        """Serialize the public key.

        Args:
            encoding (str): PEM, DER, OpenSSH, Raw or X962 (defaults to PEM).
                Raw can be used only with Ed* and X* keys.
            format (str): The supported formats are:

                - SubjectPublicKeyInfo (default)
                - PKCS1
                - OpenSSH
                - ComperssedPoint (X962 encoding only)
                - UncompressedPoint (X962 encoding only)
                - Raw (Raw encoding only; only with Ed*/X* keys)

        Returns:
            bytes: Serialized public key as bytes object.

        Raises:
            KeyError: if the encoding or format is incorrect or unsupported.
        """
        encd = encodings[encoding]
        fmt = public_format[format]
        return self._key.public_bytes(encd, fmt)

    @classmethod
    def load(cls, data, *, edwards=None):
        """Loads the public key as `bytes` object and returns
        the Key interface.

        Args:
            data (bytes, bytearray):
                The key as bytes object.

        Keyword Arguments:
            edwards (bool, NoneType):
                The password that deserializes the private key.
                `password` must be a `bytes` object if the key
                was encrypted while serialization, otherwise `None`.

        Returns:
            :any:`ECCPublicKey`: `ECCPublicKey` key interface object.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        if data.startswith(b"ecdsa-"):
            loader = ser.load_ssh_public_key

        elif data.startswith(b"-----"):
            loader = ser.load_pem_public_key

        elif data[0] == 0x30:
            loader = ser.load_der_public_key

        elif len(data) == 57:
            loader = lambda data, *args: (
                ed448.Ed448PublicKey.from_public_bytes(data)
            )

        elif len(data) == 56:
            loader = lambda data, *args: (
                x448.X448PublicKey.from_public_bytes(data)
            )

        elif len(data) == 32:
            if edwards:
                loader = lambda data, *args: (
                    ed25519.Ed25519PrivateKey.from_private_bytes(data)
                )
            else:
                loader = lambda data, *args: (
                    x25519.X25519PrivateKey.from_private_bytes(data)
                )

        else:
            raise ValueError("incorrect key format")

        try:
            key = loader(memoryview(data), defb())
            return cls(key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Incorrect key format.",
            ) from e


class _SigVerContext:
    def __init__(self, key, algo):
        self._algo = algo
        try:
            self._sign = key.sign
        except AttributeError:
            self._verify = key.verify


class ECCSignerCtx(_SigVerContext):
    """Signing context for ECC private key."""

    def sign(self, msghash):
        """Return the signature of the message hash.

        Args:
            msghash (:class:`pyflocker.ciphers.base.BaseHash`):
                The hash algorithm used to digest the object.
                Refer to :func:`pyflocker.ciphers.interfaces.Hash.new`
                function's documentation for more information about
                Hash objects.

        Returns:
            bytes: signature of the message as bytes object.
        """
        # special case 1: x* only key
        if self._algo is None:
            return self._sign(msghash.digest())

        if isinstance(msghash, Hash):
            hashalgo = msghash._hasher.algorithm
        else:
            hashalgo = Hash(
                msghash.name,
                digest_size=msghash.digest_size,
            )._hasher.algorithm

        return self._sign(
            msghash.digest(),
            self._algo(utils.Prehashed(hashalgo)),
        )


class ECCVerifierCtx(_SigVerContext):
    """Verification context for ECC public key."""

    def verify(self, msghash, signature):
        """Verifies the signature of the message hash.

        Args:
            msghash (:class:`pyflocker.ciphers.base.BaseHash`):
                The hash algorithm used to digest the object.
                Refer to :func:`pyflocker.ciphers.interfaces.Hash.new` function's
                documentation for more information about Hash objects.

            signature (bytes, bytesarray):
                signature must be a `bytes` or `bytes-like` object.

        Returns:
            None

        Raises:
            SignatureError: if the `signature` was incorrect.
        """
        # special case 1: ed* only key
        if self._algo is None:
            try:
                return self._verify(
                    signature,
                    msghash.digest(),
                )
            except bkx.InvalidSignature as e:
                raise exc.SignatureError from e

        if isinstance(msghash, Hash):
            hashalgo = msghash._hasher.algorithm
        else:
            hashalgo = Hash(
                msghash.name,
                digest_size=msghash.digest_size,
            )._hasher.algorithm

        # normal case
        try:
            return self._verify(
                signature,
                msghash.digest(),
                self._algo(utils.Prehashed(hashalgo)),
            )
        except bkx.InvalidSignature as e:
            raise exc.SignatureError from e
