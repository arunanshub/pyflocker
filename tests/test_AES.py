from __future__ import annotations

import io

import pytest
from hypothesis import Verbosity, given, settings
from hypothesis import strategies as st

from pyflocker.ciphers import AES, Backends, base, exc, modes
from pyflocker.ciphers.backends.symmetric import FileCipherWrapper
from pyflocker.ciphers.modes import Modes

from .base import get_io_buffer, make_buffer

AES_BLOCK_SIZE = 16

NORMAL_KEY_SIZES = st.sampled_from((16, 24, 32)).flatmap(
    lambda size: st.binary(min_size=size, max_size=size)
)

SIV_KEY_SIZES = st.sampled_from((32, 48, 64)).flatmap(
    lambda size: st.binary(min_size=size, max_size=size)
)


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
        enc = AES.new(
            True,
            key,
            mode,
            nonce,
            backend=backend,
            file=file,
            use_hmac=use_hmac,
        )
    except exc.UnsupportedMode:
        assert mode not in AES.supported_modes(backend)
        return pytest.skip(
            f"{mode.name} not supported by {backend.name.lower()}"
        )

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
        dec = AES.new(
            False,
            key,
            mode,
            nonce,
            backend=backend,
            file=file,
            use_hmac=use_hmac,
        )
    except exc.UnsupportedMode:
        assert mode not in AES.supported_modes(backend)
        return pytest.skip(
            f"{mode.name} not supported by {backend.name.lower()}"
        )
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
            key, mode, nonce, backend1, use_hmac=use_hmac, file=plain_file
        ),
        get_decryptor(
            key, mode, nonce, backend2, use_hmac=use_hmac, file=encrypted_file
        ),
    )


class TestAESNormal:
    @settings(deadline=None)
    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=NORMAL_KEY_SIZES,
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

    @settings(deadline=None)
    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=NORMAL_KEY_SIZES,
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

        buffer = make_buffer(data, AES_BLOCK_SIZE - 1)

        in_, out = get_io_buffer(buffer, backend1)
        encryptor.update_into(in_, out)

        in_, out = get_io_buffer(buffer, backend2)
        decryptor.update_into(in_, out)

        assert data == buffer[: len(data)].tobytes()

    @settings(deadline=None)
    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=NORMAL_KEY_SIZES,
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

    @settings(deadline=None)
    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=NORMAL_KEY_SIZES,
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
        buffer = make_buffer(data, AES_BLOCK_SIZE - 1)

        in_, out = get_io_buffer(buffer, backend1)
        encryptor.authenticate(authdata)
        encryptor.update_into(in_, out)

        in_, out = get_io_buffer(buffer, backend2)
        decryptor.authenticate(authdata)
        decryptor.update_into(in_, out)

        encryptor.finalize()
        decryptor.finalize(encryptor.calculate_tag())

        assert data == buffer[: len(data)].tobytes()

    @settings(deadline=None)
    @pytest.mark.parametrize("backend", Backends)
    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
    @given(
        key=st.binary().filter(lambda b: len(b) not in [16, 24, 32]),
        nonce=st.binary(min_size=16, max_size=16),
    )
    def test_invalid_key_length(
        self,
        key,
        mode,
        nonce,
        backend,
    ):
        with pytest.raises(ValueError):
            get_encryptor(key, mode, nonce, backend)


class TestAESSIV:
    @settings(deadline=None)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=SIV_KEY_SIZES,
        nonce=st.binary(min_size=8, max_size=16),
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
            AES.MODE_SIV,
            nonce,
            backend1,
            backend2,
        )

        assert isinstance(encryptor, base.BaseAEADOneShotCipher)
        assert isinstance(decryptor, base.BaseAEADOneShotCipher)

        assert data == decryptor.update(
            encryptor.update(data),
            encryptor.calculate_tag(),
        )

    @settings(deadline=None)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=SIV_KEY_SIZES,
        nonce=st.binary(min_size=8, max_size=16),
        data=st.binary(),
        authdata=st.none() | st.binary(min_size=1),
    )
    def test_update_into(
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
            AES.MODE_SIV,
            nonce,
            backend1,
            backend2,
        )

        assert isinstance(encryptor, base.BaseAEADOneShotCipher)
        assert isinstance(decryptor, base.BaseAEADOneShotCipher)

        if authdata is not None:
            encryptor.authenticate(authdata)
            decryptor.authenticate(authdata)

        buffer = make_buffer(data, AES_BLOCK_SIZE - 1)
        in_, out = get_io_buffer(buffer, backend1)
        encryptor.update_into(in_, out)

        in_, out = get_io_buffer(buffer, backend2)
        decryptor.update_into(in_, out, encryptor.calculate_tag())

        assert data == buffer[: len(data)].tobytes()

    @settings(deadline=None)
    @pytest.mark.parametrize("backend", Backends)
    @given(
        key=st.binary().filter(lambda b: len(b) not in [32, 48, 64]),
        nonce=st.binary(min_size=8, max_size=16),
    )
    def test_invalid_key_length(self, key, nonce, backend):
        with pytest.raises(ValueError):
            get_encryptor(key, AES.MODE_SIV, nonce, backend)

    @settings(deadline=None)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=SIV_KEY_SIZES,
        nonce=st.binary(min_size=8, max_size=16),
        data=st.binary(),
        authdata=st.binary(min_size=1),
    )
    def test_invalid_decryption(
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
            AES.MODE_SIV,
            nonce,
            backend1,
            backend2,
        )
        assert isinstance(encryptor, base.BaseAEADOneShotCipher)
        assert isinstance(decryptor, base.BaseAEADOneShotCipher)
        encryptor.authenticate(authdata)

        with pytest.raises(exc.DecryptionError):
            decryptor.update(encryptor.update(data), encryptor.calculate_tag())


class TestAESOCB:
    @settings(deadline=None)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=NORMAL_KEY_SIZES,
        nonce=st.binary(min_size=1, max_size=15),
        data=st.binary(),
        authdata=st.none() | st.binary(min_size=1),
    )
    def test_update(
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
            AES.MODE_OCB,
            nonce,
            backend1,
            backend2,
        )

        assert isinstance(encryptor, base.BaseAEADOneShotCipher)
        assert isinstance(decryptor, base.BaseAEADOneShotCipher)

        if authdata is not None:
            encryptor.authenticate(authdata)
            decryptor.authenticate(authdata)

        assert data == decryptor.update(
            encryptor.update(data),
            encryptor.calculate_tag(),
        )

    @pytest.mark.parametrize("backend", Backends)
    def test_update_into_is_unsupported(self, backend: Backends):
        encryptor = get_encryptor(
            bytes(16),
            AES.MODE_OCB,
            bytes(15),
            backend,
        )
        assert not isinstance(encryptor, FileCipherWrapper)

        buffer = make_buffer(bytes(16), AES_BLOCK_SIZE - 1)
        in_, out = get_io_buffer(buffer, backend)

        with pytest.raises(NotImplementedError):
            encryptor.update_into(in_, out)


class TestAESCCM:
    @settings(deadline=None)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=NORMAL_KEY_SIZES,
        nonce=st.binary(min_size=7, max_size=13),
        data=st.binary(),
        authdata=st.none() | st.binary(min_size=1),
    )
    def test_update(
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
            AES.MODE_CCM,
            nonce,
            backend1,
            backend2,
        )

        assert isinstance(encryptor, base.BaseAEADOneShotCipher)
        assert isinstance(decryptor, base.BaseAEADOneShotCipher)

        if authdata is not None:
            encryptor.authenticate(authdata)
            decryptor.authenticate(authdata)

        assert data == decryptor.update(
            encryptor.update(data),
            encryptor.calculate_tag(),
        )

    @settings(deadline=None, verbosity=Verbosity.verbose)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=NORMAL_KEY_SIZES,
        nonce=st.binary(min_size=7, max_size=13),
        data=st.binary(),
        authdata=st.none() | st.binary(min_size=1),
    )
    def test_update_into(
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
            AES.MODE_CCM,
            nonce,
            backend1,
            backend2,
        )

        assert isinstance(encryptor, base.BaseAEADOneShotCipher)
        assert isinstance(decryptor, base.BaseAEADOneShotCipher)

        if authdata is not None:
            encryptor.authenticate(authdata)
            decryptor.authenticate(authdata)

        buffer = make_buffer(data, AES_BLOCK_SIZE - 1)
        in_, out = get_io_buffer(buffer, backend1)

        try:
            encryptor.update_into(in_, out)
        except NotImplementedError:
            assert backend1 == Backends.CRYPTOGRAPHY
            return pytest.skip(
                f"Backend {backend1.name.lower()} does not support writing "
                "into mutable buffers."
            )

        in_, out = get_io_buffer(buffer, backend2)

        try:
            decryptor.update_into(in_, out, encryptor.calculate_tag())
        except NotImplementedError:
            assert backend2 == Backends.CRYPTOGRAPHY
            return pytest.skip(
                f"Backend {backend2.name.lower()} does not support writing "
                "into mutable buffers."
            )

        assert data == buffer[: len(data)].tobytes()

    @settings(deadline=None)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=NORMAL_KEY_SIZES,
        nonce=st.binary(min_size=7, max_size=13),
        data=st.binary(),
        authdata=st.binary(min_size=1),
    )
    def test_invalid_decryption(
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
            AES.MODE_CCM,
            nonce,
            backend1,
            backend2,
        )
        assert isinstance(encryptor, base.BaseAEADOneShotCipher)
        assert isinstance(decryptor, base.BaseAEADOneShotCipher)
        encryptor.authenticate(authdata)

        with pytest.raises(exc.DecryptionError):
            decryptor.update(encryptor.update(data), encryptor.calculate_tag())

    @settings(deadline=None)
    @pytest.mark.parametrize("backend", Backends)
    @given(
        key=st.binary().filter(lambda b: len(b) not in [16, 24, 32]),
        nonce=st.binary(min_size=7, max_size=13),
    )
    def test_invalid_key_length(self, key, nonce, backend):
        with pytest.raises(ValueError):
            get_encryptor(key, AES.MODE_CCM, nonce, backend)

    @settings(deadline=None)
    @pytest.mark.parametrize("backend", Backends)
    @given(
        key=NORMAL_KEY_SIZES,
        nonce=st.binary().filter(lambda x: len(x) not in range(7, 14)),
    )
    def test_invalid_nonce_length(self, key, nonce, backend):
        with pytest.raises(ValueError):
            get_encryptor(key, AES.MODE_CCM, nonce, backend)


class TestFileIO:
    @settings(deadline=None)
    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=NORMAL_KEY_SIZES,
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

    @settings(deadline=None)
    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @given(
        key=NORMAL_KEY_SIZES,
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

    @settings(deadline=None)
    @pytest.mark.parametrize("backend1", Backends)
    @pytest.mark.parametrize("backend2", Backends)
    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
    @given(
        key=NORMAL_KEY_SIZES,
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
    @pytest.mark.parametrize("backend", Backends)
    @pytest.mark.parametrize("mode", modes.SPECIAL)
    def test_one_shot_modes_cannot_write_to_file(
        self,
        mode: Modes,
        backend: Backends,
    ):
        file = io.BytesIO(b" ")
        with pytest.raises(NotImplementedError, match="does not support"):
            get_encryptor(
                bytes(32),
                mode,
                bytes(12),
                backend,
                file=file,
            )

    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
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

    @pytest.mark.parametrize("mode", list(modes.SPECIAL))
    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_finalize_if_tag_is_missing_for_one_shot(
        self,
        mode: Modes,
        backend: Backends,
    ):
        key, nonce = bytes(32), bytes(12)
        decryptor = get_decryptor(key, mode, nonce, backend)
        assert isinstance(decryptor, base.BaseAEADOneShotCipher)

        with pytest.raises(ValueError, match="tag is required"):
            decryptor.finalize()

    @pytest.mark.parametrize("mode", list(modes.SPECIAL))
    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_update_if_tag_is_missing_for_one_shot(
        self,
        mode: Modes,
        backend: Backends,
    ):
        key, nonce = bytes(32), bytes(12)
        decryptor = get_decryptor(key, mode, nonce, backend)
        assert isinstance(decryptor, base.BaseAEADOneShotCipher)

        with pytest.raises(ValueError, match="tag is required"):
            decryptor.update(b"somedata")

    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
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

    @pytest.mark.parametrize("mode", list(modes.SPECIAL))
    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_calculate_tag_before_finalize_for_one_shot(
        self,
        mode: Modes,
        backend: Backends,
    ):
        encryptor = get_encryptor(bytes(32), mode, bytes(12), backend)
        assert isinstance(encryptor, base.BaseAEADOneShotCipher)
        with pytest.raises(exc.NotFinalized):
            encryptor.calculate_tag()

    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
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
    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
    def test_error_on_finalize_after_finalize(
        self,
        mode: Modes,
        backend: Backends,
    ):
        encryptor = get_encryptor(bytes(32), mode, bytes(16), backend)
        encryptor.finalize()
        with pytest.raises(exc.AlreadyFinalized):
            encryptor.finalize()

    @pytest.mark.parametrize("backend", Backends)
    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.AEAD))
    def test_error_on_finalize_after_finalize_for_hmac(
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
        encryptor.finalize()
        with pytest.raises(exc.AlreadyFinalized):
            encryptor.finalize()

    @pytest.mark.parametrize("backend", Backends)
    @pytest.mark.parametrize("mode", list(modes.SPECIAL))
    def test_error_on_finalize_after_finalize_for_one_shot(
        self,
        mode: Modes,
        backend: Backends,
    ):
        encryptor = get_encryptor(bytes(32), mode, bytes(12), backend)
        encryptor.finalize()
        with pytest.raises(exc.AlreadyFinalized):
            encryptor.finalize()

    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.SPECIAL))
    @pytest.mark.parametrize("backend", Backends)
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

    @pytest.mark.parametrize("mode", list(modes.AEAD ^ modes.SPECIAL))
    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_update_and_update_into_after_finalize(
        self,
        mode: Modes,
        backend: Backends,
    ):
        encryptor = get_encryptor(bytes(32), mode, bytes(16), backend)
        assert isinstance(encryptor, base.BaseAEADCipher)
        encryptor.finalize()

        with pytest.raises(exc.AlreadyFinalized):
            encryptor.update(bytes(32))

        buffer = make_buffer(bytes(32))
        in_, out = get_io_buffer(buffer, backend)
        with pytest.raises(exc.AlreadyFinalized):
            encryptor.update_into(in_, out)

    @pytest.mark.parametrize("mode", list(set(Modes) ^ modes.AEAD))
    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_update_and_update_into_after_finalize_for_hmac(
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
            encryptor.update(bytes(32))

        buffer = make_buffer(bytes(32))
        in_, out = get_io_buffer(buffer, backend)
        with pytest.raises(exc.AlreadyFinalized):
            encryptor.update_into(in_, out)

    @pytest.mark.parametrize("mode", list(modes.SPECIAL))
    @pytest.mark.parametrize("backend", Backends)
    def test_one_shot_modes_error_on_authenticate_after_update(
        self,
        mode: Modes,
        backend: Backends,
    ):
        encryptor = get_encryptor(bytes(32), mode, bytes(12), backend)
        assert isinstance(encryptor, base.BaseAEADOneShotCipher)
        encryptor.authenticate(bytes(16))
        encryptor.update(bytes(16))

        with pytest.raises(exc.AlreadyFinalized):
            encryptor.authenticate(bytes(16))

    @pytest.mark.parametrize("mode", list(modes.SPECIAL))
    @pytest.mark.parametrize("backend", Backends)
    def test_one_shot_modes_error_on_update_after_update(
        self,
        mode: Modes,
        backend: Backends,
    ):
        encryptor = get_encryptor(bytes(32), mode, bytes(12), backend)
        assert isinstance(encryptor, base.BaseAEADOneShotCipher)
        encryptor.update(bytes(16))

        with pytest.raises(exc.AlreadyFinalized):
            encryptor.update(bytes(16))
