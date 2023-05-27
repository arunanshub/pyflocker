from __future__ import annotations

import io

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pyflocker.ciphers import Backends, base, exc
from pyflocker.ciphers.backends.symmetric import FileCipherWrapper
from pyflocker.ciphers.interfaces import ChaCha20

from .base import get_io_buffer, make_buffer

CHACHA20_BLOCK_SIZE = 1

CHACHA20_KEY_SIZES = st.binary(min_size=32, max_size=32)

CHACHA20_NONCE_SIZES = st.sampled_from((8, 12)).flatmap(
    lambda size: st.binary(min_size=size, max_size=size)
)


def get_encryptor(
    key: bytes,
    nonce: bytes,
    backend: Backends,
    *,
    use_poly1305: bool = False,
    file: io.BufferedIOBase | None = None,
) -> base.BaseAEADCipher | base.BaseNonAEADCipher | FileCipherWrapper:
    try:
        enc = ChaCha20.new(
            True,
            key,
            nonce,
            backend=backend,
            file=file,
            use_poly1305=use_poly1305,
        )
    except exc.UnsupportedAlgorithm:
        return pytest.skip(f"Camellia not supported by {backend.name.lower()}")

    assert isinstance(
        enc,
        (base.BaseAEADCipher, base.BaseNonAEADCipher, FileCipherWrapper),
    )
    return enc


def get_decryptor(
    key: bytes,
    nonce: bytes,
    backend: Backends,
    *,
    use_poly1305: bool = False,
    file: io.BufferedIOBase | None = None,
) -> base.BaseAEADCipher | base.BaseNonAEADCipher | FileCipherWrapper:
    try:
        dec = ChaCha20.new(
            False,
            key,
            nonce,
            backend=backend,
            file=file,
            use_poly1305=use_poly1305,
        )
    except exc.UnsupportedAlgorithm:
        return pytest.skip(f"Camellia not supported by {backend.name.lower()}")

    assert isinstance(
        dec,
        (
            base.BaseAEADCipher,
            base.BaseNonAEADCipher,
            FileCipherWrapper,
        ),
    )
    return dec


def get_encryptor_decryptor(
    key: bytes,
    nonce: bytes,
    backend1: Backends,
    backend2: Backends,
    *,
    use_poly1305: bool = False,
    plain_file: io.BufferedIOBase | None = None,
    encrypted_file: io.BufferedIOBase | None = None,
):
    """Return a pair of encryptor and decryptor."""
    return (
        get_encryptor(
            key,
            nonce,
            backend1,
            use_poly1305=use_poly1305,
            file=plain_file,
        ),
        get_decryptor(
            key,
            nonce,
            backend2,
            use_poly1305=use_poly1305,
            file=encrypted_file,
        ),
    )


class TestChaCha20:
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CHACHA20_KEY_SIZES,
        nonce=CHACHA20_NONCE_SIZES,
        data=st.binary(),
    )
    def test_update(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        backend1: Backends,
        backend2: Backends,
    ):
        encryptor, decryptor = get_encryptor_decryptor(
            key,
            nonce,
            backend1,
            backend2,
        )
        assert not isinstance(encryptor, FileCipherWrapper)
        assert not isinstance(decryptor, FileCipherWrapper)

        assert decryptor.update(encryptor.update(data)) == data

    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CHACHA20_KEY_SIZES,
        nonce=CHACHA20_NONCE_SIZES,
        data=st.binary(),
    )
    def test_update_into(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        backend1: Backends,
        backend2: Backends,
    ):
        encryptor, decryptor = get_encryptor_decryptor(
            key,
            nonce,
            backend1,
            backend2,
        )
        assert not isinstance(encryptor, FileCipherWrapper)
        assert not isinstance(decryptor, FileCipherWrapper)

        buffer = make_buffer(data, CHACHA20_BLOCK_SIZE - 1)

        in_, out = get_io_buffer(buffer, backend1, CHACHA20_BLOCK_SIZE - 1)
        encryptor.update_into(in_, out)

        in_, out = get_io_buffer(buffer, backend2, CHACHA20_BLOCK_SIZE - 1)
        decryptor.update_into(in_, out)

        assert data == buffer[: len(data)].tobytes()

    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CHACHA20_KEY_SIZES,
        nonce=CHACHA20_NONCE_SIZES,
        data=st.binary(),
        authdata=st.binary(min_size=1),
    )
    def test_update_with_auth(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        authdata: bytes,
        backend1: Backends,
        backend2: Backends,
    ):
        encryptor, decryptor = get_encryptor_decryptor(
            key,
            nonce,
            backend1,
            backend2,
            use_poly1305=True,
        )
        assert isinstance(encryptor, base.BaseAEADCipher)
        assert isinstance(decryptor, base.BaseAEADCipher)

        encryptor.authenticate(authdata)
        encrypted = encryptor.update(data)

        decryptor.authenticate(authdata)
        decrypted = decryptor.update(encrypted)

        encryptor.finalize()
        decryptor.finalize(encryptor.calculate_tag())

        assert data == decrypted

    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CHACHA20_KEY_SIZES,
        nonce=CHACHA20_NONCE_SIZES,
        data=st.binary(),
        authdata=st.binary(min_size=1),
    )
    def test_update_into_with_auth(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        authdata: bytes,
        backend1: Backends,
        backend2: Backends,
    ):
        encryptor, decryptor = get_encryptor_decryptor(
            key,
            nonce,
            backend1,
            backend2,
            use_poly1305=True,
        )
        assert isinstance(encryptor, base.BaseAEADCipher)
        assert isinstance(decryptor, base.BaseAEADCipher)
        buffer = make_buffer(data, CHACHA20_BLOCK_SIZE - 1)

        in_, out = get_io_buffer(buffer, backend1, CHACHA20_BLOCK_SIZE - 1)
        encryptor.authenticate(authdata)
        encryptor.update_into(in_, out)

        in_, out = get_io_buffer(buffer, backend2, CHACHA20_BLOCK_SIZE - 1)
        decryptor.authenticate(authdata)
        decryptor.update_into(in_, out)

        encryptor.finalize()
        decryptor.finalize(encryptor.calculate_tag())

        assert data == buffer[: len(data)].tobytes()

    @pytest.mark.parametrize("backend", Backends)
    @given(
        key=st.binary().filter(lambda b: len(b) != 32),
        nonce=CHACHA20_NONCE_SIZES,
    )
    def test_invalid_key_length(
        self,
        key,
        nonce,
        backend,
    ):
        with pytest.raises(ValueError):
            get_encryptor(key, nonce, backend)

    @pytest.mark.parametrize("backend", Backends)
    @given(
        key=CHACHA20_KEY_SIZES,
        # NOTE: Cryptodome supports both ChaCha20 and XChaCha20, hence the 24
        # bytes nonce. For cryptography, it should be invalid too.
        nonce=st.binary().filter(lambda b: len(b) not in (8, 12, 24)),
        use_poly1305=st.booleans(),
    )
    def test_invalid_nonce_length(
        self,
        key: bytes,
        nonce: bytes,
        backend: Backends,
        use_poly1305: bool,
    ):
        with pytest.raises(ValueError):
            get_encryptor(key, nonce, backend, use_poly1305=use_poly1305)


class TestFileIO:
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CHACHA20_KEY_SIZES,
        nonce=CHACHA20_NONCE_SIZES,
        data=st.binary(min_size=1),
        blocksize=st.integers(min_value=1, max_value=16384),
        authdata=st.none() | st.binary(min_size=1),
    )
    def test_update_into(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        blocksize: int,
        authdata: bytes,
        backend1: Backends,
        backend2: Backends,
    ):
        filebuf = io.BytesIO(data)
        as_encrypted = io.BytesIO()
        as_decrypted = io.BytesIO()

        encryptor, decryptor = get_encryptor_decryptor(
            key,
            nonce,
            backend1,
            backend2,
            plain_file=filebuf,
            encrypted_file=as_encrypted,
        )
        assert isinstance(encryptor, FileCipherWrapper)
        assert isinstance(decryptor, FileCipherWrapper)

        if authdata is not None:
            encryptor.authenticate(authdata)
            decryptor.authenticate(authdata)

        encryptor.update_into(as_encrypted, blocksize=blocksize)
        as_encrypted.seek(0)
        decryptor.update_into(
            as_decrypted,
            encryptor.calculate_tag(),
            blocksize=blocksize,
        )

        assert filebuf.getvalue() == as_decrypted.getvalue()

    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CHACHA20_KEY_SIZES,
        nonce=CHACHA20_NONCE_SIZES,
        data=st.binary(min_size=1),
        blocksize=st.integers(min_value=1, max_value=16384),
        authdata=st.none() | st.binary(min_size=1),
    )
    def test_update(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        blocksize: int,
        authdata: bytes,
        backend1: Backends,
        backend2: Backends,
    ):
        filebuf = io.BytesIO(data)
        as_encrypted = io.BytesIO()
        as_decrypted = io.BytesIO()

        encryptor, decryptor = get_encryptor_decryptor(
            key,
            nonce,
            backend1,
            backend2,
            plain_file=filebuf,
            encrypted_file=as_encrypted,
        )
        assert isinstance(encryptor, FileCipherWrapper)
        assert isinstance(decryptor, FileCipherWrapper)

        if authdata is not None:
            encryptor.authenticate(authdata)
            decryptor.authenticate(authdata)

        while True:
            enc_data = encryptor.update(blocksize)
            if enc_data is None:
                break
            as_encrypted.write(enc_data)
        as_encrypted.seek(0)

        while True:
            dec_data = decryptor.update(blocksize)
            if dec_data is None:
                break
            as_decrypted.write(dec_data)
        assert as_decrypted.getvalue() == data

    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CHACHA20_KEY_SIZES,
        nonce=CHACHA20_NONCE_SIZES,
        data=st.binary(min_size=1),
        authdata=st.binary(min_size=1),
    )
    def test_fileio_incorrect_decryption(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        authdata: bytes,
        backend1: Backends,
        backend2: Backends,
    ):
        filebuf = io.BytesIO(data)
        as_encrypted = io.BytesIO()
        as_decrypted = io.BytesIO()

        encryptor, decryptor = get_encryptor_decryptor(
            key,
            nonce,
            backend1,
            backend2,
            plain_file=filebuf,
            encrypted_file=as_encrypted,
        )
        assert isinstance(encryptor, FileCipherWrapper)
        assert isinstance(decryptor, FileCipherWrapper)

        encryptor.authenticate(authdata)

        encryptor.update_into(as_encrypted)
        as_encrypted.seek(0)

        with pytest.raises(exc.DecryptionError):
            decryptor.update_into(as_decrypted, encryptor.calculate_tag())


class TestErrors:
    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_finalize_if_tag_is_missing(self, backend: Backends):
        key, nonce = bytes(32), bytes(12)
        decryptor = get_decryptor(key, nonce, backend, use_poly1305=True)
        assert isinstance(decryptor, base.BaseAEADCipher)

        with pytest.raises(ValueError, match="tag is required"):
            decryptor.finalize()

    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_calculate_tag_before_finalize(self, backend: Backends):
        encryptor = get_encryptor(
            bytes(32),
            bytes(12),
            backend,
            use_poly1305=True,
        )
        assert isinstance(encryptor, base.BaseAEADCipher)
        with pytest.raises(exc.NotFinalized):
            encryptor.calculate_tag()

    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_authenticate_after_update(self, backend: Backends):
        encryptor = get_encryptor(
            bytes(32),
            bytes(12),
            backend,
            use_poly1305=True,
        )
        assert isinstance(encryptor, base.BaseAEADCipher)
        encryptor.authenticate(bytes(11))
        encryptor.update(bytes(32))

        with pytest.raises(TypeError):
            encryptor.authenticate(bytes(16))

    @pytest.mark.parametrize("backend", Backends)
    @given(use_hmac=st.booleans())
    def test_error_on_finalize_after_finalize(
        self,
        backend: Backends,
        use_hmac: bool,
    ):
        encryptor = get_encryptor(
            bytes(32),
            bytes(12),
            backend,
            use_poly1305=use_hmac,
        )
        encryptor.finalize()
        with pytest.raises(exc.AlreadyFinalized):
            encryptor.finalize()

    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_authenticate_after_finalize(self, backend: Backends):
        encryptor = get_encryptor(
            bytes(32),
            bytes(12),
            backend,
            use_poly1305=True,
        )
        assert isinstance(encryptor, base.BaseAEADCipher)
        encryptor.finalize()

        with pytest.raises(exc.AlreadyFinalized):
            encryptor.authenticate(bytes(16))

    @pytest.mark.parametrize("backend", Backends)
    @given(use_hmac=st.booleans())
    def test_error_on_update_and_update_into_after_finalize(
        self,
        backend: Backends,
        use_hmac: bool,
    ):
        encryptor = get_encryptor(
            bytes(32),
            bytes(12),
            backend,
            use_poly1305=use_hmac,
        )
        assert isinstance(
            encryptor,
            (
                base.BaseAEADCipher,
                base.BaseNonAEADCipher,
            ),
        )
        encryptor.finalize()

        with pytest.raises(exc.AlreadyFinalized):
            encryptor.update(bytes(32))

        buffer = make_buffer(bytes(32))
        in_, out = get_io_buffer(buffer, backend)
        with pytest.raises(exc.AlreadyFinalized):
            encryptor.update_into(in_, out)
