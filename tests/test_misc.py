from __future__ import annotations

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st
from pyflocker.ciphers.backends import Backends
from pyflocker.ciphers.backends.cryptodome_ import misc as cd_misc
from pyflocker.ciphers.backends.cryptography_ import misc as cg_misc
from pyflocker.ciphers.interfaces import Hash


@given(
    master_key=st.binary(),
    dklen=st.integers(min_value=1),
    salt=st.binary(),
    cipher_ctx=st.binary(),
    auth_ctx=st.binary(),
)
@pytest.mark.parametrize("backend", Backends)
@pytest.mark.parametrize("hashname", ["sha256", "sha512", "sha224", "sha384"])
def test_derive_hkdf_key(
    master_key: bytes,
    dklen: int,
    salt: bytes,
    cipher_ctx: bytes,
    auth_ctx: bytes,
    hashname: str,
    backend: Backends,
):
    hashalgo = Hash.new(hashname, backend=backend)
    assume(dklen < 255 * hashalgo.digest_size)

    assert cd_misc.derive_hkdf_key(
        master_key,
        dklen,
        hashalgo,
        salt,
        cipher_ctx,
        auth_ctx,
    ) == cg_misc.derive_hkdf_key(
        master_key,
        dklen,
        hashalgo,
        salt,
        cipher_ctx,
        auth_ctx,
    )


@given(nonce=st.binary().filter(lambda x: len(x) not in (8, 12)))
def test_error_poly1305_nonce_length_invalid(nonce: bytes):
    with pytest.raises(ValueError, match="Poly1305 nonce must"):
        cg_misc.derive_poly1305_key(bytes(32), nonce)


def test_error_if_hashalgo_is_invalid():
    with pytest.raises(TypeError):
        cg_misc.derive_hkdf_key(
            b"!",
            32,
            "NOT-A-TYPE",  # type:ignore
            b"S",
            b"",
            b"",
        )

    with pytest.raises(TypeError):
        cd_misc.derive_hkdf_key(
            b"!",
            32,
            "NOT-A-TYPE",  # type:ignore
            b"S",
            b"",
            b"",
        )
