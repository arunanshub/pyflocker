"""
Miscellaneous Tools: Tools that are not common to symmetric or asymmetric.
"""

from __future__ import annotations

from Cryptodome.Protocol import KDF

from pyflocker.ciphers.base import BaseHash


def derive_hkdf_key(
    master_key: bytes,
    dklen: int,
    hashalgo: BaseHash,
    salt: bytes,
    cipher_ctx: bytes = b"enc-key",
    auth_ctx: bytes = b"auth-key",
) -> tuple[bytes, bytes]:
    """Derive key materials for HMAC from given master key.

    Args:
        master_key: The key used to derive the keys from.
        dklen: Desired lenth of the derived key.
        hashalgo: The name of the hash algorithm.
        salt: The salt to use.
        cipher_ctx: Context for cipher.
        auth_ctx: Context for HMAC.

    Returns:
        A pair of *cipher key* and *MAC key*.
    """
    if not isinstance(hashalgo, BaseHash):
        msg = "hashalgo must be an object implementing BaseHash."
        raise TypeError(msg)

    hash_ = hashalgo.new()

    key = KDF.HKDF(
        master=master_key,
        key_len=dklen,
        salt=salt,
        hashmod=hash_,  # type: ignore
        num_keys=1,
        context=cipher_ctx,
    )
    assert isinstance(key, bytes)

    hkey = KDF.HKDF(
        master=master_key,
        key_len=hash_.digest_size,
        salt=salt,
        hashmod=hash_,  # type: ignore
        num_keys=1,
        context=auth_ctx,
    )
    assert isinstance(hkey, bytes)
    return key, hkey
