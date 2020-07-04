from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS

from .. import _asymmetric as _asym
from ._hashes import hashes as _hashes

padding = {
    _asym.OAEP: PKCS1_OAEP.new,
    _asym.PSS: PKCS1_PSS.new,
    _asym.MGF1: PKCS1_OAEP.MGF1,
}

# required for limiting invalid interactions
encodings = {
    'PEM': 'PEM',
    'DER': 'DER',
    'OpenSSH': 'OpenSSH',
}

formats = {
    'PKCS1': 1,
    'PKCS8': 8,
}

# PKCS#8 password derivation mechanisms
protection_schemes = frozenset((
    'PBKDF2WithHMAC-SHA1AndAES128-CBC',
    'PBKDF2WithHMAC-SHA1AndAES192-CBC',
    'PBKDF2WithHMAC-SHA1AndAES256-CBC',
    'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
    'scryptAndAES128-CBC',
    'scryptAndAES192-CBC',
    'scryptAndAES256-CBC',
))


class _RSAKey:
    @property
    def n(self):
        return self._key.n

    @property
    def e(self):
        return self._key.e

    @classmethod
    def load(cls, data, password=None):
        return cls(key=RSA.import_key(data, password))


class RSAPrivateKey(_RSAKey):
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

    def decryptor(self, padding=_asym.OAEP()):
        return RSADecryptionCtx(self._key, padding)

    def signer(self, padding=_asym.PSS()):
        return RSASignerCtx(self._key, padding)

    def public_key(self):
        return RSAPublicKey(self._key.publickey())

    def serialize(self,
                  encoding='PEM',
                  format='PKCS8',
                  passphrase=None,
                  *,
                  protection=None):
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


class RSAPublicKey(_RSAKey):
    def __init__(self, key):
        self._key = key

    def encryptor(self, padding=_asym.OAEP()):
        return RSAEncryptionCtx(self._key, padding)

    def verifier(self, padding=_asym.PSS()):
        return RSAVerifierCtx(self._key, padding)

    def serialize(self, encoding='PEM'):
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
    def encrypt(self, ciphertext):
        return self._cipher.encrypt(ciphertext)


class RSADecryptionCtx(CipherContext):
    def decrypt(self, ciphertext):
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
        return self._sig.sign(msghash._hasher)


class RSAVerifierCtx(SigVerContext):
    def verify(self, msghash, signature):
        return self._sig.verify(msghash._hasher, signature)
