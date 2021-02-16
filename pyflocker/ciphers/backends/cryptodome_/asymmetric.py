from functools import partial
from types import MappingProxyType

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pss

from .. import asymmetric


def get_OAEP(key, padding):
    """Construct a Cryptodome specific OAEP object.

    Args:
        key: Public/Private key (from the Cryptodome backend).
        padding (OAEP): An OAEP object.

    Returns:
        OAEP object:
            An OAEP encryptor/decryptor object depending on the key, from the
            Cryptodome backend.
    """
    if isinstance(mgf := padding.mgf, asymmetric.MGF1):
        mgf = partial(PKCS1_OAEP.MGF1, hash_gen=padding.mgf.hashfunc.new())

    return PKCS1_OAEP.new(
        key,
        padding.hashfunc.new(),
        mgf,
        padding.label or b"",
    )


def get_PSS(key, padding):
    """Construct a Cryptodome specific PSS object.

    Args:
        key: Public/Private key (from the Cryptodome backend).
        padding (PSS): A PSS object.

    Returns:
        PSS object: An PSS signer/verifier object, depending on the key.
    """
    if isinstance(mgf := padding.mgf, asymmetric.MGF1):
        mgf = partial(PKCS1_OAEP.MGF1, hash_gen=padding.mgf.hashfunc.new())

    if padding.salt_length is None:
        return _SaltLengthMaximizer(key, padding)

    return pss.new(
        key,
        mask_func=mgf,
        salt_bytes=padding.salt_length,
    )


class _SaltLengthMaximizer:
    """
    Custom sign/verify wrapper over PSS to preserve consistency:
    pyca/cryptography follows the OpenSSL quirk where the default
    salt length is maximized and doesn't match with the size of the
    digest applied to the message.
    """

    def __init__(self, key, padding):
        self._key = key
        self._padding = padding

    def _sign_or_verify(self, msghash, signature=None):
        salt_length = self._key.size_in_bytes() - msghash.digest_size - 2
        pss = get_PSS(
            self._key,
            type(self._padding)(self._padding.mgf, salt_length),
        )
        if signature is None:
            return pss.sign(msghash)
        return pss.verify(msghash, signature)

    def sign(self, msghash):
        if not self._key.has_private():
            raise TypeError("The key is not a private key.")
        return self._sign_or_verify(msghash)

    def verify(self, msghash, signature):
        return self._sign_or_verify(msghash, signature)


PADDINGS = MappingProxyType(
    {
        asymmetric.OAEP: get_OAEP,
        asymmetric.PSS: get_PSS,
    }
)

del MappingProxyType


def get_padding(padding):
    """Return the appropriate padding object based on ``padding``."""
    return PADDINGS[type(padding)]
