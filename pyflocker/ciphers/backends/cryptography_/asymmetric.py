from types import MappingProxyType

from cryptography.hazmat.primitives import serialization as serial
from cryptography.hazmat.primitives.asymmetric import padding as padding_

from .. import asymmetric
from . import Hash


def get_OAEP(padding):
    """Construct a pyca/cryptography specific OAEP object.

    Args:
        padding (OAEP): An OAEP object.

    Returns:
        OAEP object:
            An OAEP encryptor/decryptor object depending on the key, from the
            cryptography backend.
    """
    if not isinstance(padding, asymmetric.OAEP):
        raise TypeError("padding must be an instance of OAEP.")
    if not isinstance(padding.mgf, asymmetric.MGF1):
        raise TypeError("MGF must be an instance of MGF1.")
    return padding_.OAEP(
        mgf=padding_.MGF1(
            Hash._get_hash_algorithm(padding.mgf.hashfunc),
        ),
        algorithm=Hash._get_hash_algorithm(padding.hashfunc),
        label=padding.label,
    )


def get_PSS(padding):
    """Construct a pyca/cryptography specific PSS object.

    Args:
        padding (PSS): A PSS object.

    Returns:
        PSS object: An PSS signer/verifier object, depending on the key.
    """
    if not isinstance(padding, asymmetric.PSS):
        raise TypeError("padding must be an instance of PSS.")
    if not isinstance(padding.mgf, asymmetric.MGF1):
        raise TypeError("MGF must be an instance of MGF1.")
    return padding_.PSS(
        mgf=padding_.MGF1(Hash._get_hash_algorithm(padding.mgf.hashfunc)),
        salt_length=padding.salt_length or padding_.PSS.MAX_LENGTH,
    )


PADDINGS = MappingProxyType(
    {
        asymmetric.OAEP: get_OAEP,
        asymmetric.PSS: get_PSS,
    }
)


ENCODINGS = MappingProxyType(
    {
        "PEM": serial.Encoding.PEM,
        "DER": serial.Encoding.DER,
        "OpenSSH": serial.Encoding.OpenSSH,
        "Raw": serial.Encoding.Raw,
        "X962": serial.Encoding.X962,
    }
)


try:
    _fmt = dict(OpenSSH=serial.PrivateFormat.OpenSSH)
except AttributeError:
    _fmt = dict()

PRIVATE_FORMATS = MappingProxyType(
    {
        "PKCS8": serial.PrivateFormat.PKCS8,
        "TraditionalOpenSSL": serial.PrivateFormat.TraditionalOpenSSL,
        "Raw": serial.PrivateFormat.Raw,
        # PKCS1 name compat with Cryptodome
        "PKCS1": serial.PrivateFormat.TraditionalOpenSSL,
        **_fmt,
    }
)


PUBLIC_FORMATS = MappingProxyType(
    {
        "SubjectPublicKeyInfo": serial.PublicFormat.SubjectPublicKeyInfo,
        "PKCS1": serial.PublicFormat.PKCS1,
        "OpenSSH": serial.PublicFormat.OpenSSH,
        "CompressedPoint": serial.PublicFormat.CompressedPoint,
        "UncompressedPoint": serial.PublicFormat.UncompressedPoint,
        "Raw": serial.PublicFormat.Raw,
    }
)

PARAMETER_FORMATS = MappingProxyType(
    {
        "PKCS3": serial.ParameterFormat.PKCS3,
    }
)

del MappingProxyType, _fmt


def get_padding_func(padding):
    """Return the appropriate padding factory function based on ``padding``."""
    return PADDINGS[type(padding)]
