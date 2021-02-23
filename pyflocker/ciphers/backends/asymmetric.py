"""Tools for asymmetric ciphers common to all the backends."""

import typing
from dataclasses import dataclass, field

from .. import base
from ..interfaces import Hash


def _default_hash_factory():
    """SHA-256 Hash object factory.

    The import is delayed because we want the backends to be loaded
    only when they are explicitly called by user or loaded by the
    backend loader.
    """
    return Hash.new("sha256")


@dataclass(frozen=True)
class MGF1:
    """
    Mask Generation Function.

    Attributes:
        hashfunc:
            A :any:`BaseHash` object. Defaults to 'sha256'.
    """

    hashfunc: base.BaseHash = field(default_factory=_default_hash_factory)


@dataclass(frozen=True)
class OAEP:
    """
    PKCS#1 OAEP is an asymmetric cipher based on RSA and OAEP padding.
    It can encrypt messages slightly shorter than RSA modulus.

    Attributes:
        mgf: Mask Generation Function. Defaults to MGF1.
        hashfunc:
            A :any:`BaseHash` object. Defaults to 'sha256'.
            Can be created from :func:`pyflocker.ciphers.interfaces.Hash.new`
            function.
        label: A label to apply to this encryption. Defaults to ``None``.
    """

    mgf: MGF1 = field(default_factory=MGF1)
    hashfunc: base.BaseHash = field(default_factory=_default_hash_factory)
    label: typing.Optional[bytes] = None


@dataclass(frozen=True)
class PSS:
    """
    Probabilistic Digital Signature Scheme.

    Attributes:
        mgf: A Mask Generation Function. Defaults to MGF1.
        salt_length:
            Length of the salt, in bytes.
            Length must be greater than 0. Defaults to ``None``.
    """

    mgf: MGF1 = field(default_factory=MGF1)
    salt_length: typing.Optional[int] = None
