from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ._hashes import hashes
from ._serialization import encodings, private_format, public_format
from .._asymmetric import PSS

curves = {
    'secp256r1': ec.SECP256R1,
    'secp384r1': ec.SECP384R1,
    'secp521r1': ec.SECP521R1,
    'secp224r1': ec.SECP224R1,
    'secp192r1': ec.SECP192R1,
    'secp256k1': ec.SECP256K1,
}

exchange_algorithms = {
    'ECDH': ec.ECDH,
}

signature_algorithms = {
    'ECDSA': ec.ECDSA,
}


class ECCPrivateKey:
    def __init__(self, curve=None, **kwargs):
        if kwargs:
            self._key = kwargs.pop('key')
        else:
            self._key = ec.generate_private_key(curves[curve], defb())

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
        if isinstance(peer_public_key, (bytes, bytearray, memoryview)):
            peer_public_key = ECCPublicKey.load(peer_public_key)

        return self._key.exchange(
            exchange_algorithms[algorithm](),
            peer_public_key._key,
        )

    def signer(self, algorithm='ECDSA'):
        """Returns a signer context."""
        return ECCSignerCtx(self._key, algorithm)

    @classmethod
    def load(cls, data, password=None):
        """Loads the private key and returns a Key interface.

        `password` must be a `bytes` object if the key was encrypted
        while serialization, otherwise `None`.
        """
        if data.startswith(b'-----BEGIN OPENSSH PRIVATE KEY'):
            key = ser.load_ssh_private_key(data, password)

        elif data.startswith(b'-----'):
            key = ser.load_pem_private_key(data, password, defb())

        elif data[0] == 0x30:
            key = ser.load_der_private_key(data, password, defb())

        else:
            raise ValueError('incorrect key format')
        return cls(key=key)


class ECCPublicKey:
    def __init__(self, key):
        self._key = key

    def verifier(self, algorithm='ECDSA'):
        """Returns a verifier context using the given 1algorithm`"""
        return ECCVerifierCtx(self._key, algorithm)

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
            key = ser.load_ssh_public_key(data, defb())

        elif data.startswith(b'-----'):
            key = ser.load_pem_public_key(data, defb())

        elif data[0] == 0x30:
            key = ser.load_der_public_key(data, defb())

        else:
            raise ValueError('incorrect key format')
        return cls(key=key)


class SigVerContext:
    def __init__(self, key, algo):
        self._algo = signature_algorithms[algo]
        try:
            self._sign = key.sign
        except AttributeError:
            self._verify = key.verify


class ECCSignerCtx(SigVerContext):
    def sign(self, msghash):
        """Return the signature of the message hash.
        
        `mhash` must be an instance of `BaseHash` and must be
        generated with the same backend as of the ECC key.

        Refer to `Hash.new` function's documentation.
        """
        return self._sign(
            msghash.digest(),
            self._algo(utils.Prehashed(hashes[msghash._name]())),
        )


class ECCVerifierCtx(SigVerContext):
    def verify(self, msghash, signature):
        """Verifies the signature of the message hash.

        `mhash` must be an instance of `BaseHash` and must be
        generated with the same backend as of the ECC key.
        Refer to `Hash.new` function's documentation.
 
        `signature` must be a `bytes` or `bytes-like` object.
        """
        return self._verify(
            signature,
            msghash.digest(),
            self._algo(utils.Prehashed(hashes[msghash._name]())),
        )
