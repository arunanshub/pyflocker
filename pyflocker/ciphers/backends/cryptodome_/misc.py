"""
Miscellaneous Tools: Tools that are not common to symmetric or asymmetric.
"""

from __future__ import annotations

import typing

from Cryptodome.Protocol import KDF

from ...base import BaseHash
from . import Hash


def derive_hkdf_key(
    master_key: bytes,
    dklen: int,
    hashalgo: typing.Union[str, BaseHash],
    salt: bytes,
    cipher_ctx: bytes = b"enc-key",
    auth_ctx: bytes = b"auth-key",
) -> typing.Tuple[bytes, bytes]:
    """Derive key materials for HMAC from given master key.

    Args:
        master_key (bytes): The key used to derive the keys from.
        dklen (int): Desired lenth of the derived key.
        hashalgo (str, BaseHash): The name of the hash algorithm.
        salt (bytes): The salt to use.
        cipher_ctx (bytes): Context for cipher.
        auth_ctx (bytes): Context for HMAC.

    Returns:
        tuple[bytes, bytes]: A pair of *cipher key* and *MAC key*.
    """
    if not isinstance(hashalgo, (str, BaseHash)):
        raise TypeError(
            "hashalgo must be a str or an object implementing BaseHash."
        )

    if isinstance(hashalgo, str):
        hash_ = Hash.new(hashalgo)
    else:
        # use our hashalgo
        hash_ = hashalgo.new()

    key = KDF.HKDF(
        master=master_key,
        key_len=dklen,
        salt=salt,
        hashmod=hash_,
        num_keys=1,
        context=cipher_ctx,
    )

    hkey = KDF.HKDF(
        master=master_key,
        key_len=hash_.digest_size,
        salt=salt,
        hashmod=hash_,
        num_keys=1,
        context=auth_ctx,
    )
    return key, hkey
