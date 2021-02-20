from functools import partial
from types import MappingProxyType

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import DSS, pss

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


def get_DSS(key, mode, encoding):
    """Construct a Cryptodome specific DSS object.

    Args:
        key: The private/public key from Cryptodome backend.
        mode (str):
            The mode can be:

            - 'fips-186-3'
            - 'deterministic-rfc6979'
        encoding:
            How the signature is encoded. Values are:

            - 'binary'
            - 'der'

    Returns:
        DSS object: DSS object from Cryptodome backend.

    Raises:
        ValueError: if the mode or encoding is invalid.
    """
    try:
        return DSS.new(
            key,
            mode=DSS_MODES[mode],
            encoding=DSS_ENCODINGS[encoding],
        )
    except KeyError as e:
        raise ValueError(f"The mode or encoding is invalid: {e.args}")


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


ENCODINGS = MappingProxyType(
    {
        "PEM": "PEM",
        "DER": "DER",
        "OpenSSH": "OpenSSH",
    }
)

FORMATS = MappingProxyType(
    {
        "PKCS1": 1,
        "PKCS8": 8,
    }
)

# PKCS8 password derivation mechanisms
PROTECTION_SCHEMES = frozenset(
    (
        "PBKDF2WithHMAC-SHA1AndAES128-CBC",
        "PBKDF2WithHMAC-SHA1AndAES192-CBC",
        "PBKDF2WithHMAC-SHA1AndAES256-CBC",
        "PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC",
        "scryptAndAES128-CBC",
        "scryptAndAES192-CBC",
        "scryptAndAES256-CBC",
    )
)


DSS_ENCODINGS = MappingProxyType(
    {
        "binary": "binary",
        "der": "der",
    }
)

DSS_MODES = MappingProxyType(
    {
        "fips-186-3": "fips-186-3",
        "deterministic-rfc6979": "deterministic-rfc6979",
    }
)


def get_padding_func(padding):
    """Return the appropriate padding factory function based on ``padding``."""
    return PADDINGS[type(padding)]


del MappingProxyType
