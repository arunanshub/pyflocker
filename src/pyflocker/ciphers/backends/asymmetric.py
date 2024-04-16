"""Tools for asymmetric ciphers common to all the backends."""

from __future__ import annotations

import typing
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pyflocker.ciphers.base import (
    BaseAsymmetricPadding,
    BaseEllepticCurveExchangeAlgorithm,
    BaseEllepticCurveSignatureAlgorithm,
    BaseMGF,
)
from pyflocker.ciphers.interfaces import Hash

if TYPE_CHECKING:  # pragma: no cover
    from pyflocker.ciphers.base import BaseHash


def _default_hash_factory() -> BaseHash:
    """SHA-256 Hash object factory.

    The import is delayed because we want the backends to be loaded
    only when they are explicitly called by user or loaded by the
    backend loader.
    """
    return Hash.new("sha256")


@dataclass(frozen=True)
class MGF1(BaseMGF):
    """
    Mask Generation Function.

    Parameters:
        hashfunc:
            A :any:`BaseHash` object. Defaults to 'sha256'.
    """

    hashfunc: BaseHash = field(default_factory=_default_hash_factory)


@dataclass(frozen=True)
class OAEP(BaseAsymmetricPadding):
    """
    PKCS#1 OAEP is an asymmetric cipher based on RSA and OAEP padding.
    It can encrypt messages slightly shorter than RSA modulus.

    Parameters:
        mgf: Mask Generation Function. Defaults to MGF1.
        hashfunc:
            A :any:`BaseHash` object. Defaults to 'sha256'. Can be created from
            :func:`.interfaces.Hash.new` function.
        label: A label to apply to this encryption. Defaults to ``None``.
    """

    mgf: BaseMGF = field(default_factory=MGF1)
    hashfunc: BaseHash = field(default_factory=_default_hash_factory)
    label: bytes | None = None
    name: typing.ClassVar[str] = "OAEP"


@dataclass(frozen=True)
class PSS(BaseAsymmetricPadding):
    """
    Probabilistic Digital Signature Scheme.

    Parameters:
        mgf: A Mask Generation Function. Defaults to MGF1.
        salt_length:
            Length of the salt, in bytes. It must be greater than 0. Defaults
            to ``None``.
    """

    mgf: BaseMGF = field(default_factory=MGF1)
    salt_length: int | None = None
    name: typing.ClassVar[str] = "PSS"


@dataclass(frozen=True)
class ECDSA(BaseEllepticCurveSignatureAlgorithm):
    """
    Elleptic Curve Digital Signature Algorithm.
    """


@dataclass(frozen=True)
class ECDH(BaseEllepticCurveExchangeAlgorithm):
    """
    Elleptic Curve Diffie Hellmann Algorithm.
    """


@dataclass(frozen=True)
class EdDSA(BaseEllepticCurveSignatureAlgorithm):
    """
    Edwards-curve Digital Signature Algorithm.

    Parameters:
        mode: A string that is currently equal to ``"rfc8032"``.
        context:
            Up to 255 bytes of context, which is a constant byte string to
            segregate different protocols or different applications of the same
            key.
    """

    mode: str = "rfc8032"
    context: bytes | None = None
