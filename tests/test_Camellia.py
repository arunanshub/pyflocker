from __future__ import annotations

import io

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyflocker.ciphers import base, exc
from pyflocker.ciphers.backends import Backends
from pyflocker.ciphers.backends.symmetric import FileCipherWrapper
from pyflocker.ciphers.interfaces import Camellia
from pyflocker.ciphers.modes import Modes

from .base import get_io_buffer, make_buffer

CAMELLIA_BLOCK_SIZE = 16

CAMELLIA_KEY_SIZES = st.sampled_from((16, 24, 32)).flatmap(
    lambda size: st.binary(min_size=size, max_size=size)
)

CAMELLIA_MODES = (Modes.MODE_CTR, Modes.MODE_CFB, Modes.MODE_OFB)


def get_encryptor(
    key: bytes,
    mode: Modes,
    nonce: bytes,
    backend: Backends,
    *,
    use_hmac: bool = False,
    file: io.BufferedIOBase | None = None,
) -> base.BaseAEADCipher | base.BaseNonAEADCipher | FileCipherWrapper:
    try:
        enc = Camellia.new(
            True,
            key,
            mode,
            nonce,
            backend=backend,
            file=file,
            use_hmac=use_hmac,
        )
    except exc.UnsupportedMode:
        assert mode not in Camellia.supported_modes(backend)
        return pytest.skip(
            f"{mode.name} not supported by {backend.name.lower()}"
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
    mode: Modes,
    nonce: bytes,
    backend: Backends,
    *,
    use_hmac: bool = False,
    file: io.BufferedIOBase | None = None,
) -> base.BaseAEADCipher | base.BaseNonAEADCipher | FileCipherWrapper:
    try:
        dec = Camellia.new(
            False,
            key,
            mode,
            nonce,
            backend=backend,
            file=file,
            use_hmac=use_hmac,
        )
    except exc.UnsupportedMode:
        assert mode not in Camellia.supported_modes(backend)
        return pytest.skip(
            f"{mode.name} not supported by {backend.name.lower()}"
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
    mode: Modes,
    nonce: bytes,
    backend1: Backends,
    backend2: Backends,
    *,
    use_hmac: bool = False,
    plain_file: io.BufferedIOBase | None = None,
    encrypted_file: io.BufferedIOBase | None = None,
):
    """Return a pair of encryptor and decryptor."""
    return (
        get_encryptor(
            key,
            mode,
            nonce,
            backend1,
            use_hmac=use_hmac,
            file=plain_file,
        ),
        get_decryptor(
            key,
            mode,
            nonce,
            backend2,
            use_hmac=use_hmac,
            file=encrypted_file,
        ),
    )


class TestCamellia:
    @pytest.mark.parametrize("mode", CAMELLIA_MODES)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CAMELLIA_KEY_SIZES,
        nonce=st.binary(min_size=16, max_size=16),
        data=st.binary(),
    )
    def test_update(
        self,
        key: bytes,
        mode: Modes,
        nonce: bytes,
        data: bytes,
        backend1: Backends,
        backend2: Backends,
    ):
        encryptor, decryptor = get_encryptor_decryptor(
            key,
            mode,
            nonce,
            backend1,
            backend2,
        )
        assert not isinstance(encryptor, FileCipherWrapper)
        assert not isinstance(decryptor, FileCipherWrapper)

        assert decryptor.update(encryptor.update(data)) == data

    @pytest.mark.parametrize("mode", CAMELLIA_MODES)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CAMELLIA_KEY_SIZES,
        nonce=st.binary(min_size=16, max_size=16),
        data=st.binary(),
    )
    def test_update_into(
        self,
        key: bytes,
        mode: Modes,
        nonce: bytes,
        data: bytes,
        backend1: Backends,
        backend2: Backends,
    ):
        encryptor, decryptor = get_encryptor_decryptor(
            key,
            mode,
            nonce,
            backend1,
            backend2,
        )
        assert not isinstance(encryptor, FileCipherWrapper)
        assert not isinstance(decryptor, FileCipherWrapper)

        buffer = make_buffer(data, CAMELLIA_BLOCK_SIZE - 1)

        in_, out = get_io_buffer(buffer, backend1)
        encryptor.update_into(in_, out)

        in_, out = get_io_buffer(buffer, backend2)
        decryptor.update_into(in_, out)

        assert data == buffer[: len(data)].tobytes()

    @pytest.mark.parametrize("mode", CAMELLIA_MODES)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CAMELLIA_KEY_SIZES,
        nonce=st.binary(min_size=16, max_size=16),
        data=st.binary(),
        authdata=st.binary(min_size=1),
    )
    def test_update_with_auth(
        self,
        key: bytes,
        mode: Modes,
        nonce: bytes,
        data: bytes,
        authdata: bytes,
        backend1: Backends,
        backend2: Backends,
    ):
        encryptor, decryptor = get_encryptor_decryptor(
            key,
            mode,
            nonce,
            backend1,
            backend2,
            use_hmac=True,
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

    @pytest.mark.parametrize("mode", CAMELLIA_MODES)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CAMELLIA_KEY_SIZES,
        nonce=st.binary(min_size=16, max_size=16),
        data=st.binary(),
        authdata=st.binary(min_size=1),
    )
    def test_update_into_with_auth(
        self,
        key: bytes,
        mode: Modes,
        nonce: bytes,
        data: bytes,
        authdata: bytes,
        backend1: Backends,
        backend2: Backends,
    ):
        encryptor, decryptor = get_encryptor_decryptor(
            key,
            mode,
            nonce,
            backend1,
            backend2,
            use_hmac=True,
        )
        assert isinstance(encryptor, base.BaseAEADCipher)
        assert isinstance(decryptor, base.BaseAEADCipher)
        buffer = make_buffer(data, CAMELLIA_BLOCK_SIZE - 1)

        in_, out = get_io_buffer(buffer, backend1)
        encryptor.authenticate(authdata)
        encryptor.update_into(in_, out)

        in_, out = get_io_buffer(buffer, backend2)
        decryptor.authenticate(authdata)
        decryptor.update_into(in_, out)

        encryptor.finalize()
        decryptor.finalize(encryptor.calculate_tag())

        assert data == buffer[: len(data)].tobytes()


class TestFileIO:
    @pytest.mark.parametrize("mode", CAMELLIA_MODES)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CAMELLIA_KEY_SIZES,
        nonce=st.binary(min_size=16, max_size=16),
        data=st.binary(min_size=1),
        authdata=st.none() | st.binary(min_size=1),
    )
    def test_update_into(
        self,
        key: bytes,
        mode: Modes,
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
            mode,
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

        encryptor.update_into(as_encrypted)
        as_encrypted.seek(0)
        decryptor.update_into(as_decrypted, encryptor.calculate_tag())

        assert filebuf.getvalue() == as_decrypted.getvalue()

    @pytest.mark.parametrize("mode", CAMELLIA_MODES)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=CAMELLIA_KEY_SIZES,
        nonce=st.binary(min_size=16, max_size=16),
        data=st.binary(min_size=1),
        authdata=st.none() | st.binary(min_size=1),
    )
    def test_update(
        self,
        key: bytes,
        mode: Modes,
        nonce: bytes,
        data: bytes,
        authdata: bytes,
        backend1: Backends,
        backend2: Backends,
    ):
        filebuf = io.BytesIO(data)
        as_encrypted = io.BytesIO()

        encryptor, decryptor = get_encryptor_decryptor(
            key,
            mode,
            nonce,
            backend1,
            backend2,
            plain_file=filebuf,  # type: ignore
            encrypted_file=as_encrypted,  # type: ignore
        )
        assert isinstance(encryptor, FileCipherWrapper)
        assert isinstance(decryptor, FileCipherWrapper)

        if authdata is not None:
            encryptor.authenticate(authdata)
            decryptor.authenticate(authdata)

        as_encrypted.write(encryptor.update(len(data)))  # type: ignore
        as_encrypted.seek(0)

        as_decrypted = decryptor.update(len(data))
        assert as_decrypted == data

    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @pytest.mark.parametrize("mode", CAMELLIA_MODES)
    @given(
        key=CAMELLIA_KEY_SIZES,
        nonce=st.binary(min_size=16, max_size=16),
        data=st.binary(min_size=1),
        authdata=st.binary(min_size=1),
    )
    def test_fileio_incorrect_decryption(
        self,
        key: bytes,
        mode: Modes,
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
            mode,
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
    @pytest.mark.parametrize("mode", CAMELLIA_MODES)
    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_finalize_if_tag_is_missing(
        self,
        mode: Modes,
        backend: Backends,
    ):
        key, nonce = bytes(32), bytes(16)
        decryptor = get_decryptor(key, mode, nonce, backend, use_hmac=True)
        assert isinstance(decryptor, base.BaseAEADCipher)

        with pytest.raises(ValueError, match="tag is required"):
            decryptor.finalize()

    @pytest.mark.parametrize("mode", CAMELLIA_MODES)
    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_calculate_tag_before_finalize(
        self,
        mode: Modes,
        backend: Backends,
    ):
        encryptor = get_encryptor(
            bytes(32),
            mode,
            bytes(16),
            backend,
            use_hmac=True,
        )
        assert isinstance(encryptor, base.BaseAEADCipher)
        with pytest.raises(exc.NotFinalized):
            encryptor.calculate_tag()

    @pytest.mark.parametrize("mode", CAMELLIA_MODES)
    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_authenticate_after_update(
        self,
        mode: Modes,
        backend: Backends,
    ):
        encryptor = get_encryptor(
            bytes(32),
            mode,
            bytes(16),
            backend,
            use_hmac=True,
        )
        assert isinstance(encryptor, base.BaseAEADCipher)
        encryptor.authenticate(bytes(11))
        encryptor.update(bytes(32))

        with pytest.raises(TypeError):
            encryptor.authenticate(bytes(16))

    @pytest.mark.parametrize("backend", Backends)
    @given(
        mode=st.sampled_from(CAMELLIA_MODES),
        use_hmac=st.booleans(),
    )
    def test_error_on_finalize_after_finalize(
        self,
        mode: Modes,
        backend: Backends,
        use_hmac: bool,
    ):
        encryptor = get_encryptor(
            bytes(32),
            mode,
            bytes(16),
            backend,
            use_hmac=use_hmac,
        )
        encryptor.finalize()
        with pytest.raises(exc.AlreadyFinalized):
            encryptor.finalize()

    @given(
        mode=st.sampled_from(CAMELLIA_MODES),
        backend=st.sampled_from(Backends),
    )
    def test_error_on_authenticate_after_finalize(
        self,
        mode: Modes,
        backend: Backends,
    ):
        encryptor = get_encryptor(
            bytes(32),
            mode,
            bytes(16),
            backend,
            use_hmac=True,
        )
        assert isinstance(encryptor, base.BaseAEADCipher)
        encryptor.finalize()

        with pytest.raises(exc.AlreadyFinalized):
            encryptor.authenticate(bytes(16))

    @pytest.mark.parametrize("backend", Backends)
    @given(
        mode=st.sampled_from(CAMELLIA_MODES),
        use_hmac=st.booleans(),
    )
    def test_error_on_update_and_update_into_after_finalize(
        self,
        mode: Modes,
        backend: Backends,
        use_hmac: bool,
    ):
        encryptor = get_encryptor(
            bytes(32),
            mode,
            bytes(16),
            backend,
            use_hmac=use_hmac,
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
