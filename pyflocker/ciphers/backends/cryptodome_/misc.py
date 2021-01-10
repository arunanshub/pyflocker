try:
    from Cryptodome.Protocol import KDF
except ModuleNotFoundError:
    from Crypto.Protocol import KDF

from .Hash import hashes as _hashes


def derive_hkdf_key(master_key, dklen, hashalgo, salt):
    """Derive key materials for HMAC from given master key."""
    key = KDF.HKDF(
        master=master_key,
        key_len=dklen,
        salt=salt,
        hashmod=_hashes[hashalgo](),
        num_keys=1,
        context=b"enc-key",
    )

    hash_ = _hashes[hashalgo]()
    hkey = KDF.HKDF(
        master=master_key,
        key_len=hash_.digest_size,
        salt=salt,
        hashmod=hash_,
        num_keys=1,
        context=b"auth-key",
    )
    return key, hkey
