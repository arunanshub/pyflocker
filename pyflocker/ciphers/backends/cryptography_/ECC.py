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

from ._hashes import hashes, Hash
from .. import base, exc
from ._serialization import encodings, private_format, public_format
from .._asymmetric import PSS

curves = {
    'secp256r1': ec.SECP256R1,
    'secp384r1': ec.SECP384R1,
    'secp521r1': ec.SECP521R1,
    'secp224r1': ec.SECP224R1,
    'secp192r1': ec.SECP192R1,
    'secp256k1': ec.SECP256K1,

    # aliases for PyCryptodome
    # note that only those curves are aliased which are
    # currently supported by the same.
    'NIST P-256': ec.SECP256R1,
    'p256': ec.SECP256R1,
    'P-256': ec.SECP256R1,
    'prime256v1': ec.SECP256R1,
    'NIST P-384': ec.SECP384R1,
    'p384': ec.SECP384R1,
    'P-384': ec.SECP384R1,
    'prime384v1': ec.SECP384R1,
    'NIST P-521': ec.SECP521R1,
    'p521': ec.SECP521R1,
    'P-521': ec.SECP521R1,
    'prime521v1': ec.SECP521R1,
}

# some special cases which require extra handling...
special_curves = {
    'x448': x448.X448PrivateKey,
    'x25519': x25519.X25519PrivateKey,
    'ed448': ed448.Ed448PrivateKey,
    'ed25519': ed25519.Ed25519PrivateKey,
}

# ...but they are still curves
curves.update(special_curves)

exchange_algorithms = {
    'ECDH': ec.ECDH,
}

signature_algorithms = {
    'ECDSA': ec.ECDSA,
}


class ECCPrivateKey(base.BasePrivateKey):
    """Represents ECC private key."""
    def __init__(self, curve=None, **kwargs):
        if kwargs:
            self._key = kwargs.pop('key')
        else:
            if curve not in special_curves:
                self._key = ec.generate_private_key(
                    curves[curve],
                    defb(),
                )
            else:
                self._key = curves[curve].generate()

    def public_key(self):
        """Returns public key from the private key"""
        return ECCPublicKey(self._key.public_key())

    def serialize(self, encoding='PEM', format='PKCS8', passphrase=None):
        """Serialize the private key.

        - `encoding` can be PEM or DER (defaults to PEM).
        - The `format` can be:
            - PKCS8 (default)
            - TraditionalOpenSSL
            - OpenSSH (available from pyca/cryptography version >=3.X)
            - PKCS1 (alias to TraditionalOpenSSL for PyCryptodome(x) compat)

        - `passphrase` must be a bytes object.
          If `passphrase` is None, the private key will be exported
          in the clear!
        """
        encd = encodings[encoding]
        fmt = private_format[format]
        if passphrase is None:
            prot = ser.NoEncryption()
        else:
            prot = ser.BestAvailableEncryption(
                memoryview(passphrase).tobytes())
        return self._key.private_bytes(encd, fmt, prot)

    def exchange(self, peer_public_key, algorithm='ECDH'):
        """Perform a key exchange and return shared secret as
        bytes object.

        The `peer_public_key` can be a `ECCPublicKey` object or
        a serialized public key. If latter is the case, the key
        is loaded and then the exchange is performed.
        """
        if not hasattr(self._key, 'exchange'):
            raise NotImplementedError

        if isinstance(peer_public_key, (bytes, bytearray, memoryview)):
            peer_public_key = ECCPublicKey.load(peer_public_key)

        if not hasattr(self._key, 'sign'):
            return self._key.exchange(peer_public_key._key)

        return self._key.exchange(
            exchange_algorithms[algorithm](),
            peer_public_key._key,
        )

    def signer(self, algorithm='ECDSA'):
        """Returns a signer context."""
        # special case 1: x* key
        if not hasattr(self._key, 'sign'):
            raise NotImplementedError
        # special case 2: ed* key
        if not hasattr(self._key, 'exchange'):
            return ECCSignerCtx(self._key, None)

        return ECCSignerCtx(self._key, signature_algorithms[algorithm])

    @classmethod
    def load(cls, data, password=None):
        """Loads the private key and returns a Key interface.

        `password` must be a `bytes` object if the key was encrypted
        while serialization, otherwise `None`.
        """
        if data.startswith(b'-----BEGIN OPENSSH PRIVATE KEY'):
            loader = ser.load_ssh_private_key

        elif data.startswith(b'-----'):
            loader = ser.load_pem_private_key

        elif data[0] == 0x30:
            loader = ser.load_der_private_key

        else:
            raise ValueError('incorrect key format')

        # type check
        if password is not None:
            password = memoryview(password)

        try:
            return cls(key=loader(
                memoryview(data),
                password,
                defb(),
            ), )
        except (ValueError, TypeError) as e:
            raise ValueError(
                'Cannot deserialize key. '
                'Either Key format is invalid or '
                'password is missing or incorrect.', ) from e


class ECCPublicKey(base.BasePublicKey):
    """Represents ECC public key."""
    def __init__(self, key):
        self._key = key

    def verifier(self, algorithm='ECDSA'):
        """Returns a verifier context using the given 1algorithm`"""
        # Special case 1: x* only key
        if not hasattr(self._key, 'verify'):
            raise NotImplementedError

        # Special case 2: ed* only key
        if not hasattr(self._key, 'curve'):
            return ECCVerifierCtx(self._key, None)
        return ECCVerifierCtx(self._key, signature_algorithms[algorithm])

    def serialize(self, encoding='PEM', format='SubjectPublicKeyInfo'):
        """Serialize the public key.

        - `encoding` can be PEM, DER, OpenSSH, X962 (defaults to PEM).
        - `format` can be:
            - SubjectPublicKeyInfo (default)
            - PKCS1
            - OpenSSH
            - ComperssedPoint
            - UncompressedPoint
        """
        encd = encodings[encoding]
        fmt = public_format[format]
        return self._key.public_bytes(encd, fmt)

    @classmethod
    def load(cls, data):
        """Loads the public key and returns a Key interface."""
        if data.startswith(b'ecdsa-'):
            loader = ser.load_ssh_public_key

        elif data.startswith(b'-----'):
            loader = ser.load_pem_public_key

        elif data[0] == 0x30:
            loader = ser.load_der_public_key

        else:
            raise ValueError('incorrect key format')

        try:
            return cls(key=loader(memoryview(data), defb()))
        except ValueError as e:
            raise ValueError(
                'Cannot deserialize key. '
                'Incorrect key format.', ) from e


class SigVerContext:
    def __init__(self, key, algo):
        self._algo = algo
        try:
            self._sign = key.sign
        except AttributeError:
            self._verify = key.verify


class ECCSignerCtx(SigVerContext):
    """Signing context for ECC private key."""
    def sign(self, msghash):
        """Return the signature of the message hash.
        
        `mhash` must be an instance of `BaseHash` and must be
        generated with the same backend as of the ECC key.

        Refer to `Hash.new` function's documentation.
        """
        if not isinstance(msghash, Hash):
            raise TypeError(
                'the message hashing object must be instantiated '
                'from the same backend as that of the ECC key.', )
        # special case 1: x* only key
        if self._algo is None:
            return self._sign(msghash.digest())

        return self._sign(
            msghash.digest(),
            self._algo(utils.Prehashed(hashes[msghash._name]())),
        )


class ECCVerifierCtx(SigVerContext):
    """Verification context for ECC public key."""
    def verify(self, msghash, signature):
        """Verifies the signature of the message hash.

        `mhash` must be an instance of `BaseHash` and must be
        generated with the same backend as of the ECC key.
        Refer to `Hash.new` function's documentation.
 
        `signature` must be a `bytes` or `bytes-like` object.
        """
        if not isinstance(msghash, Hash):
            raise TypeError(
                'the message hashing object must be instantiated '
                'from the same backend as that of the ECC key.', )
        
        # special case 1: ed* only key
        if self._algo is None:
            try:
                return self._verify(
                    signature,
                    msghash.digest(),
                )
            except bkx.InvalidSignature as e:
                raise exc.SignatureError from e

        # normal case
        try:
            return self._verify(
                signature,
                msghash.digest(),
                self._algo(utils.Prehashed(hashes[msghash._name]())),
            )
        except bkx.InvalidSignature as e:
            raise exc.SignatureError from e
