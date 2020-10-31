from collections import namedtuple
from ..interfaces import Hash

MGF1 = namedtuple(
    "MGF1",
    "hash",
    defaults=[Hash.new("sha256")],
)

MGF1.__doc__ = """\
Mask Generation Function.

Args:
    hash: A `pyflocker.ciphers.base.BaseHash` object.
        Defaults to 'sha256'.

Returns:
    MGF1 object.
"""

OAEP = namedtuple(
    "OAEP",
    "mgf, hash, label",
    defaults=[MGF1(), Hash.new("sha256"), None],
)

OAEP.__doc__ = """\
PKCS#1 OAEP is an asymmetric cipher based on RSA and OAEP padding.

It can encrypt messages slightly shorter than RSA modulus.

Args:
    mgf: Mask Generation Function. Defaults to MGF1.
    hash: A `pyflocker.ciphers.base.BaseHash` object. Defaults to 'sha256'.
        Can be created from `pyflocker.ciphers.interfaces.Hash.new` function.
    label: A label to apply to this encryption. Defaults to `None`.

Returns:
    OAEP object.
"""

PSS = namedtuple(
    "PSS",
    "mgf, salt_len",
    defaults=[MGF1(), None],
)

PSS.__doc__ = """\
Probabilistic Digital Signature Scheme.

Args:
    mgf: A Mask Generation Function. Defaults to MGF1.
    salt_len: Length of the salt, in bytes.
        Length must be greater than 0. Defaults to `None`.

Returns:
    PSS object.
"""
