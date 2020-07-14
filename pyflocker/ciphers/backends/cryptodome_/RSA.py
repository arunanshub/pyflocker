from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS

from .. import base
from .._asymmetric import OAEP, PSS, MGF1
from ._hashes import hashes as _hashes
from ._serialization import encodings, formats, protection_schemes

padding = {
    OAEP: PKCS1_OAEP.new,
    PSS: PKCS1_PSS.new,
    MGF1: PKCS1_OAEP.MGF1,
}


class _RSAKey:
    @property
    def n(self):
        return self._key.n

    @property
    def e(self):
        return self._key.e

    @classmethod
    def load(cls, data, password=None):
        """Loads the public or private key as `bytes` object
        and returns the Key interface.

        `password` must be a `bytes` object if the key was encrypted
        while serialization, otherwise `None`.
        `password` has no meaning for public key.
        """
        return cls(key=RSA.import_key(data, password))


class RSAPrivateKey(_RSAKey, base.BasePrivateKey):
    """RSA private key wrapper class."""
    def __init__(self, n=None, e=65537, **kwargs):
        if kwargs:
            self._key = kwargs.pop('key')
        else:
            if n is None:
                raise ValueError('modulus not provided')
            self._key = RSA.generate(n, e=e)

    @property
    def p(self):
        return self._key.p

    @property
    def q(self):
        return self._key.q

    @property
    def d(self):
        return self._key.d

    @property
    def u(self):
        return self._key.u

    def decryptor(self, padding=OAEP()):
        """
        Returns a decryption context with OAEP padding and MGF1
        as mask generation function.
        """
        return RSADecryptionCtx(self._key, padding)

    def signer(self, padding=PSS()):
        """
        Returns a signer context.

        `padding` is PSS, and the default hash function used
        by PSS and MGF1 (the default mask generation function)
        is `sha256`.
        """
        return RSASignerCtx(self._key, padding)

    def public_key(self):
        """Returns public key from the private key"""
        return RSAPublicKey(self._key.publickey())

    def serialize(self,
                  encoding='PEM',
                  format='PKCS8',
                  passphrase=None,
                  *,
                  protection=None):
        """Serialize the private key.

        - `encoding` can be PEM or DER (defaults to PEM).
        - The `format` can be PKCS1 or PKCS8 (defaults to PKCS8).
        - `passphrase` must be a bytes object.
          If `passphrase` is None, the private key will be exported
          in the clear!
        - Supplying a value for protection has meaning only if
          the `format` is PKCS8.
          If None is provided, PBKDF2WithHMAC-SHA1AndAES256-CBC is
          used as the protection scheme
        """
        if encoding not in encodings.keys() ^ {'OpenSSH'}:
            raise TypeError('encoding must be PEM or DER')

        if protection is not None:
            if protection not in protection_schemes:
                raise TypeError('invalid protection scheme')

        if format == 'PKCS1' and protection is not None:
            raise TypeError('protection is meaningful only for PKCS8')

        if passphrase is not None and protection is None:
            # use a curated encryption choice and not DES-EDE3-CBC
            protection = 'PBKDF2WithHMAC-SHA1AndAES256-CBC'

        return self._key.export_key(
            format=encodings[encoding],
            pkcs=formats[format],
            passphrase=(memoryview(passphrase).tobytes()
                        if passphrase is not None else None),
            protection=protection,
        )


class RSAPublicKey(_RSAKey, base.BasePublicKey):
    """RSA Public Key wrapper class."""
    def __init__(self, key):
        self._key = key

    def encryptor(self, padding=OAEP()):
        """
        Returns a encryption context with OAEP padding and MGF1
        as mask generation function.
        """
        return RSAEncryptionCtx(self._key, padding)

    def verifier(self, padding=PSS()):
        """
        Returns a verifier context.

        `padding` is PSS, and the default hash function used
        by PSS and MGF1 (the default mask generation function)
        is `sha256`.
 
        """
        return RSAVerifierCtx(self._key, padding)

    def serialize(self, encoding='PEM'):
        """Serialize the private key.

        - `encoding` can be PEM, DER or OpenSSH (defaults to PEM).
        """
        return self._key.export_key(format=encodings[encoding])


def _get_padding(pad):
    _pad = padding[pad.__class__]
    mhash = _hashes[pad.mgf.hash]()
    _mgf = lambda x, y: padding[pad.mgf.__class__](x, y, mhash)
    return _pad, _mgf


def _get_cipher(key, pad):
    _pad, _mgf = _get_padding(pad)
    phash = _hashes[pad.hash]()
    return _pad(key, hashAlgo=phash, mgfunc=_mgf)


class CipherContext:
    def __init__(self, key, padding):
        self._cipher = _get_cipher(key, padding)


class RSAEncryptionCtx(CipherContext):
    def encrypt(self, plaintext):
        """Encrypts the plaintext and returns the ciphertext.

        `plaintext` must be a `bytes` or `bytes-like` object.
        """
        return self._cipher.encrypt(plaintext)


class RSADecryptionCtx(CipherContext):
    def decrypt(self, ciphertext):
        """Decrypts the ciphertext and returns the plaintext.

        `ciphertext` must be a `bytes` or `bytes-like` object.
        """
        return self._cipher.decrypt(ciphertext)


def _get_signer(key, pad):
    _pad, _mgf = _get_padding(pad)
    if pad.salt_len is None:
        return _pad(key, mgfunc=_mgf)
    return _pad(key, mgfunc=_mgf, saltLen=pad.salt_len)


class SigVerContext:
    def __init__(self, key, padding):
        self._sig = _get_signer(key, padding)


class RSASignerCtx(SigVerContext):
    def sign(self, msghash):
        """Return the signature of the message hash.
        
        `msghash` must be an instance of `BaseHash` and must be
        instantiated from the same backend as that of the RSA key.
        Refer to `Hash.new` function's documentation.
        """
        return self._sig.sign(msghash._hasher)


class RSAVerifierCtx(SigVerContext):
    def verify(self, msghash, signature):
        """Verifies the signature of the message hash.

        `msghash` must be an instance of `BaseHash` and must be
        instantiated from the same backend as of the RSA key.
        Refer to `Hash.new` function's documentation.
 
        `signature` must be a `bytes` or `bytes-like` object.
        """
        return self._sig.verify(msghash._hasher, signature)
