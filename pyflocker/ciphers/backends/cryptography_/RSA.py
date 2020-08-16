from functools import partial

import cryptography.exceptions as bkx
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    padding as pads,
    utils,
)

from .. import base, exc, Backends
from .._asymmetric import OAEP, MGF1, PSS
from ._hashes import Hash
from ._serialization import encodings, private_format, public_format

paddings = {
    OAEP: pads.OAEP,
    MGF1: pads.MGF1,
    PSS: pads.PSS,
}

_supported_encodings = frozenset((
    'PEM',
    'DER',
    'OpenSSH',
))


class _RSANumbers:
    def _numbers(self):
        try:
            k = self._key.public_numbers()
        except AttributeError:
            k = self._key.private_numbers().public_numbers
        return k

    @property
    def e(self):
        return self._numbers().e

    @property
    def n(self):
        return self._numbers().n


class RSAPrivateKey(_RSANumbers, base.BasePrivateKey):
    def __init__(self, n=None, e=65537, **kwargs):
        if kwargs:
            # we have the key made beforehand
            # or from some classmethod
            self._key = kwargs.pop('key')
        else:
            if n is None:
                raise ValueError('modulus not provided')
            self._key = rsa.generate_private_key(e, n, defb())

        # numbers
        nos = self._key.private_numbers()
        self._p = nos.p
        self._q = nos.q

    @property
    def p(self):
        return self._p

    @property
    def q(self):
        return self._q

    def public_key(self):
        """Creates a public key from the private key

        Args:
            None

        Returns:
            RSAPublicKey interface.
        """
        return RSAPublicKey(self._key.public_key())

    def decryptor(self, padding=OAEP()):
        """Creates a decryption context

        Args:
            padding: The padding to use. Default is OAEP.

        Returns:
            RSADecryptionCtx for decrypting ciphertexts.
        """
        return RSADecryptionCtx(self._key, padding)

    def signer(self, padding=PSS()):
        """Create a signer context.

        Args:
            padding: The padding to use. Default is PSS.

        Returns:
            A RSASignerCtx object for signing messages.
        """
        return RSASignerCtx(self._key, padding)

    def serialize(self, encoding='PEM', format='PKCS8', passphrase=None):
        """Serialize the private key.

        Args:
            encoding: PEM or DER (defaults to PEM).
            format: The formats can be:
              - PKCS8 (default)
              - TraditionalOpenSSL
              - OpenSSH (available from pyca/cryptography version >=3.X)
              - PKCS1 (alias to TraditionalOpenSSL for
                PyCryptodome(x) compat)
            passphrase:
            A bytes-like object to protect the private key.
            If `passphrase` is None, the private key will
            be exported in the clear!

        Returns:
            The private key as a bytes object.

        Raises:
           KeyError:
                if the format or encoding is invalid or not supported.
        """
        if encoding not in _supported_encodings ^ {'OpenSSH'}:
            raise TypeError('Encoding must be PEM or DER')

        encd = encodings[encoding]
        fmt = private_format[format]
        if passphrase is None:
            prot = ser.NoEncryption()
        else:
            prot = ser.BestAvailableEncryption(
                memoryview(passphrase).tobytes())
        return self._key.private_bytes(encd, fmt, prot)

    @classmethod
    def load(cls, data, password=None):
        """Loads the private key as `bytes` object and returns
        the Key interface.

        Args:
            data:
                The key as bytes object.
            password:
                The password that deserializes the private key.
                `password` must be a `bytes` object if the key
                was encrypted while serialization, otherwise `None`.

        Returns:
            RSAPrivateKey interface object.

        Raises:
            ValueError if the key could  not be deserialized.
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


class RSAPublicKey(_RSANumbers, base.BasePublicKey):
    """RSA Public Key wrapper class."""
    def __init__(self, key):
        self._key = key

    def encryptor(self, padding=OAEP()):
        """Creates a encryption context

        Args:
            padding: The padding to use. Defaults to OAEP.

        Returns:
            An RSAEncryptionCtx encryption context object.
        """
        return RSAEncryptionCtx(self._key, padding)

    def verifier(self, padding=PSS()):
        """Creates a verifier context.

        Args:
            padding: The padding to use. Defaults to ECC.

        Returns:
            RSAVerifierCtx verification context object.
        """
        return RSAVerifierCtx(self._key, padding)

    def serialize(self, encoding='PEM', format='SubjectPublicKeyInfo'):
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
            KeyError: if the encoding or format is incorrect or unsupported.
        """
        encd = encodings[encoding]
        fmt = public_format[format]
        return self._key.public_bytes(encd, fmt)

    @classmethod
    def load(cls, data):
        """Loads the public key as `bytes` object and returns
        the Key interface.

        Args:
            data:
                The key as bytes object.

        Returns:
            RSAPublicKey key interface object.

        Raises:
            ValueError if the key could not be deserialized.
        """
        if data.startswith(b'ssh-rsa '):
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


def _get_padding(pad):
    _pad = paddings[pad.__class__]
    _mgf = paddings[pad.mgf.__class__]  # backend MGF class
    mgf = _mgf(
        Hash(
            pad.mgf.hash.name,
            digest_size=pad.mgf.hash.digest_size,
        )._hasher.algorithm)
    return _pad, mgf


class Context:
    def __init__(self, key, padding):
        pad, mgf = _get_padding(padding)
        try:
            enc_or_dec = key.encrypt
        except AttributeError:
            enc_or_dec = key.decrypt

        self._encrypt_or_decrypt = partial(
            enc_or_dec,
            padding=pad(
                mgf,
                Hash(
                    padding.hash.name,
                    digest_size=padding.hash.digest_size,
                )._hasher.algorithm,
                padding.label,
            ),
        )


class RSAEncryptionCtx(Context):
    def encrypt(self, plaintext):
        """Encrypts the plaintext and returns the ciphertext.

        Args:
            plaintext: a `bytes` or `bytes-like` object.

        Returns:
            encrypted bytes object.
        """
        return self._encrypt_or_decrypt(plaintext)


class RSADecryptionCtx(Context):
    def decrypt(self, ciphertext):
        """Decrypts the ciphertext and returns the plaintext.

        Args:
            ciphertext: a `bytes` or `bytes-like` object.

        Returns:
            decrypted plaintext.

        Raises:
            DecryptionError: if the decryption was not successful.
        """
        try:
            return self._encrypt_or_decrypt(ciphertext)
        except ValueError as e:
            raise exc.DecryptionError from e


class SigVerContext:
    def __init__(self, key, padding):
        pad, mgf = _get_padding(padding)
        salt_len = (padding.salt_len
                    if padding.salt_len is not None else pad.MAX_LENGTH)

        try:
            sig_ver = key.sign
        except AttributeError:
            sig_ver = key.verify

        self._sign_or_verify = partial(
            sig_ver,
            padding=pad(
                mgf,
                salt_len,
            ),
        )


class RSASignerCtx(SigVerContext):
    def sign(self, msghash):
        """Return the signature of the message hash.

        Args:
            msghash:
                It must be a `Hash` object, used to digest the message to sign.

        Returns:
            signature of the message as bytes object.

        Raises:
            TypeError: if the `msghash` object is not from the same
                backend.
        """
        if isinstance(msghash, Hash):
            hashalgo = msghash._hasher.algorithm
        else:
            hashalgo = Hash(
                msghash.name,
                digest_size=msghash.digest_size,
            )._hasher.algorithm

        return self._sign_or_verify(
            msghash.digest(),
            algorithm=utils.Prehashed(hashalgo),
        )


class RSAVerifierCtx(SigVerContext):
    def verify(self, msghash, signature):
        """Verifies the signature of the message hash.

        Args:
            msghash:
                It must be a `Hash` object, used to digest the message to sign.

            signature:
                signature must be a `bytes` or `bytes-like` object.

        Returns:
            None

        Raises:
            SignatureError: if the `signature` was incorrect.
        """
        if isinstance(msghash, Hash):
            hashalgo = msghash._hasher.algorithm
        else:
            hashalgo = Hash(
                msghash.name,
                digest_size=msghash.digest_size,
            )._hasher.algorithm

        try:
            return self._sign_or_verify(
                signature,
                msghash.digest(),
                algorithm=utils.Prehashed(hashalgo),
            )
        except bkx.InvalidSignature as e:
            raise exc.SignatureError from e
