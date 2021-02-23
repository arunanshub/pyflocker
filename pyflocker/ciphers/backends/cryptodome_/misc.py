"""
Miscellaneous Tools: Tools that are not common to symmetric or asymmetric.
"""

import typing

from Cryptodome.Protocol import KDF

from ...base import BaseHash
from . import Hash


def derive_hkdf_key(
    master_key: typing.ByteString,
    dklen: int,
    hashalgo: typing.Union[str, BaseHash],
    salt: typing.ByteString,
    cipher_ctx: typing.ByteString = b"enc-key",
    auth_ctx: typing.ByteString = b"auth-key",
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
    if isinstance(hashalgo, str):
        hash_ = Hash.new(hashalgo)
    elif isinstance(hashalgo, BaseHash):
        # use our hashalgo
        hash_ = hashalgo.new()
    else:
        raise TypeError(
            "hashalgo must be a str or an object implementing BaseHash."
        )

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
