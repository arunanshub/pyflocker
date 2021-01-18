"""
Miscellaneous Tools: Tools that are not common to symmetric or asymmetric.
"""

try:
    from Cryptodome.Protocol import KDF
except ModuleNotFoundError:
    from Crypto.Protocol import KDF

from .Hash import hashes as _hashes


def derive_hkdf_key(
    master_key,
    dklen,
    hashalgo,
    salt,
    cipher_ctx=b"enc-key",
    auth_ctx=b"auth-key",
):
    """Derive key materials for HMAC from given master key.

    Args:
        master_key (bytes): The key used to derive the keys from.
        dklen (int): Desired lenth of the derived key.
        hashalgo (str): The name of the hash algorithm.
        salt (bytes): The salt to use.
        cipher_ctx (bytes): Context for cipher.
        auth_ctx (bytes): Context for HMAC.

    Returns:
        tuple[bytes, bytes]: A pair of *cipher key* and *MAC key*.
    """
    hash_ = _hashes[hashalgo]()
    key = KDF.HKDF(
        master=master_key,
        key_len=dklen,
        salt=salt,
        hashmod=_hash,
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
