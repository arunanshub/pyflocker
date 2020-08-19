try:
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_OAEP
    from Cryptodome.Signature import PKCS1_PSS
except ModuleNotFoundError:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Signature import PKCS1_PSS

from .. import base, exc
from .._asymmetric import OAEP, PSS, MGF1
from ._hashes import Hash
from ._serialization import encodings, formats, protection_schemes

paddings = {
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

        Args:
            data:
                The key as bytes object.
            password:
                The password that deserializes the private key.
                `password` must be a `bytes` object if the key
                was encrypted while serialization, otherwise `None`.
                `password` has no meaning for public key.

        Returns:
            RSAPrivateKey or RSAPublicKey interface depending upon the
            key.

        Raises:
            ValueError if the key could  not be deserialized.
        """
        try:
            return cls(key=RSA.import_key(data, password))
        except ValueError as e:
            raise ValueError(
                'Cannot deserialize key. '
                'Either Key format is invalid or '
                'password is missing or incorrect.', ) from e


class RSAPrivateKey(_RSAKey, base.BasePrivateKey):
    """RSA private key wrapper class."""
    def __init__(self, n=None, e=65537, **kwargs):
        if kwargs:
            self._key = kwargs.pop('key')
        else:
            if n is None:
                raise ValueError('RSA modulus not provided')
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

    def public_key(self):
        """Creates a public key from the private key

        Args:
            None

        Returns:
            RSAPublicKey interface.
        """
        return RSAPublicKey(self._key.publickey())

    def serialize(self,
                  encoding='PEM',
                  format='PKCS8',
                  passphrase=None,
                  *,
                  protection=None):
        """Serialize the private key.

        Args:
            encoding:
                PEM or DER (defaults to PEM).
            format:
                PKCS1 or PKCS8 (defaults to PKCS8).
            passphrase:
                a bytes object to use for encrypting the private key.
                If `passphrase` is None, the private key will be exported
                in the clear!

        Kwargs:
            protection:
                The protection scheme to use.

                Supplying a value for protection has meaning only if the
                `format` is PKCS8. If `None` is provided
                `PBKDF2WithHMAC-SHA1AndAES256-CBC` is used as the protection
                scheme.

        Returns:
            Serialized key as a bytes object.

        Raises:
            ValueError:
                If the encoding is incorrect or,
                if DER is used with PKCS1 or protection value
                is supplied with PKCS1 format.
            KeyError: if the format is invalid or not supported.
       """
        if encoding not in encodings.keys() ^ {'OpenSSH'}:
            raise ValueError('encoding must be PEM or DER')

        if protection is not None:
            if protection not in protection_schemes:
                raise ValueError('invalid protection scheme')

        if format == 'PKCS1':
            if protection is not None:
                raise ValueError('protection is meaningful only for PKCS8')
            if encoding == 'DER':
                raise ValueError('cannot use DER with PKCS1 format')

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

    def serialize(self, encoding='PEM'):
        """Serialize the private key.

        Args:
            encoding: PEM, DER or OpenSSH (defaults to PEM).

        Returns:
            The serialized public key as bytes object.

        Raises:
            KeyError: if the encoding is not supported or invalid.
        """
        return self._key.export_key(format=encodings[encoding])


def _get_padding(pad):
    _pad = paddings[pad.__class__]
    mhash = Hash(pad.mgf.hash.name,
                 digest_size=pad.mgf.hash.digest_size)  #._hasher
    _mgf = lambda x, y: paddings[pad.mgf.__class__](x, y, mhash)
    return _pad, _mgf


def _get_cipher(key, pad):
    _pad, _mgf = _get_padding(pad)
    phash = Hash(pad.hash.name, digest_size=pad.hash.digest_size)  #._hasher
    return _pad(key, hashAlgo=phash, mgfunc=_mgf)


class CipherContext:
    def __init__(self, key, padding):
        self._cipher = _get_cipher(key, padding)


class RSAEncryptionCtx(CipherContext):
    def encrypt(self, plaintext):
        """Encrypts the plaintext and returns the ciphertext.

        Args:
            plaintext: a `bytes` or `bytes-like` object.

        Returns:
            encrypted bytes object.

        Raises:
            ValueError:
                if the message is too long to encrypt with
                the given key.
        """
        try:
            return self._cipher.encrypt(plaintext)
        except ValueError as e:
            raise ValueError('the message is too long') from e


class RSADecryptionCtx(CipherContext):
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
            return self._cipher.decrypt(ciphertext)
        except ValueError as e:
            raise exc.DecryptionError from e


def _get_signer(key, pad):
    _pad, _mgf = _get_padding(pad)
    if pad.salt_len is None:

        @staticmethod
        def sign_or_verify(msghash, signature=None):
            """
            Custom sign/verify wrapper over PSS to preserve consistency:
            pyca/cryptography follows the OpenSSL quirk where the default
            salt length is maximized and doesn't match with the size of the
            digest applied to the message.

            Args:
                msghash: The Hash object used to digest the message to sign.
                signature: The signature as bytes object.
                    If signature is None, signing is performed, otherwise
                    verification is performed.

            Returns:
                signature as bytes object if signature argument is None.
                None if signature argument is provided.
            """
            salt_len = key.size_in_bytes() - msghash.digest_size - 2
            sigver = _pad(key, mgfunc=_mgf, saltLen=salt_len)
            if signature is None:
                return sigver.sign(msghash)
            return sigver.verify(msghash, signature)

        # create an object placeholder object to hold the signer/verifier.
        funcs = dict(sign=sign_or_verify, verify=sign_or_verify)
        svobj = type('_OpenSSLStyleSigVer', (), funcs)()
        return svobj

    return _pad(key, mgfunc=_mgf, saltLen=pad.salt_len)


class SigVerContext:
    def __init__(self, key, padding):
        self._sig = _get_signer(key, padding)


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
            ValueError: if the key is not long enough to sign the
                massage.
        """
        try:
            return self._sig.sign(msghash)
        except ValueError as e:
            raise ValueError('RSA key is not long enough') from e


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
        if not self._sig.verify(msghash, signature):
            raise exc.SignatureError
