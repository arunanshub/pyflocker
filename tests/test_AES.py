"""
Simple tests for AES

These tests are meant to check the API and hence, do not use
the official test vectors. The backends used by pyflocker
implements the tests using the required test vectors.
"""
import os
from functools import partial
from itertools import product

import pytest

from pyflocker.ciphers import AES, exc, modes
from pyflocker.ciphers.backends import Backends

from .base import BaseSymmetric, BaseSymmetricAEAD

_LENGTH_NORMAL = (16, 24, 32)
_LENGTH_SPECIAL_SIV = (32, 48, 64)
_MODE_NON_AEAD = set(modes.Modes) ^ modes.aead


@pytest.fixture
def cipher(key_length, mode, use_hmac, iv_length, backend1, backend2):
    if mode not in AES.supported_modes(backend1):
        pytest.skip(f"{backend1} doesn't support {mode}")
    elif mode not in AES.supported_modes(backend2):
        pytest.skip(f"{backend2} doesn't support {mode}")

    return partial(
        AES.new,
        key=os.urandom(key_length),
        mode=mode,
        iv_or_nonce=os.urandom(iv_length),
        use_hmac=use_hmac,
    )


@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize(
    "key_length",
    _LENGTH_NORMAL,
)
@pytest.mark.parametrize(
    "mode",
    _MODE_NON_AEAD,
)
@pytest.mark.parametrize(
    "use_hmac",
    [False],
)
@pytest.mark.parametrize(
    "iv_length",
    [16],
)
class TestNonAEAD(BaseSymmetric):
    def test_update_into(self, cipher, backend1, backend2):
        return super().test_update_into(cipher, backend1, backend2, offset=15)


@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize(
    "key_length",
    _LENGTH_NORMAL,
)
@pytest.mark.parametrize(
    "mode",
    set(modes.Modes) ^ modes.special,
)
@pytest.mark.parametrize(
    "use_hmac",
    [True],
)
@pytest.mark.parametrize(
    "iv_length",
    [16],
)
class TestAEAD(BaseSymmetricAEAD):
    def test_update_into(self, cipher, backend1, backend2):
        return super().test_update_into(cipher, backend1, backend2, offset=15)

    def test_update_into_with_auth(
        self,
        cipher,
        backend1,
        backend2,
    ):
        return super().test_update_into_with_auth(
            cipher,
            backend1,
            backend2,
            offset=15,
        )


@pytest.mark.parametrize(
    "use_hmac",
    [True],
)
@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
class _TestAEADOneShot(BaseSymmetricAEAD):
    @staticmethod
    def _assert_update(enc, dec, data):
        ctxt = enc.update(data)
        ptxt = dec.update(ctxt, enc.calculate_tag())
        assert ptxt == data

    @staticmethod
    def _assert_update_into(enc, dec, readbuf, in_, out):
        try:
            enc.update_into(readbuf, in_)
        except NotImplementedError:
            pytest.skip(f"update_into not supported by {enc.mode}")
        except TypeError:
            assert enc.mode == modes.Modes.MODE_OCB
            pytest.skip(
                f"{enc.mode} does not suport writing into mutable buffers."
            )

        try:
            dec.update_into(in_[: len(readbuf)], out, enc.calculate_tag())
        except NotImplementedError:
            pytest.skip(f"update_into not supported by {dec.mode}")
        except TypeError:
            assert dec.mode == modes.Modes.MODE_OCB
            pytest.skip(
                f"{dec.mode} does not suport writing into mutable buffers."
            )

        assert out[: len(readbuf)].tobytes() == readbuf.tobytes()

    @staticmethod
    def _finalizer(enc, dec):
        # one shot ciphers are finalized on their first call to update(_into)
        pass

    def test_update_into(self, cipher, backend1, backend2):
        return super().test_update_into(cipher, backend1, backend2, offset=15)

    def test_update_into_with_auth(
        self,
        cipher,
        backend1,
        backend2,
    ):
        return super().test_update_into_with_auth(
            cipher,
            backend1,
            backend2,
            offset=15,
        )

    def test_update_into_file_buffer(self, cipher, backend1, backend2):
        with pytest.raises(NotImplementedError):
            super().test_update_into_file_buffer(cipher, backend1, backend2)


@pytest.mark.parametrize(
    "mode",
    [modes.Modes.MODE_SIV],
)
@pytest.mark.parametrize(
    "key_length",
    _LENGTH_SPECIAL_SIV,
)
@pytest.mark.parametrize(
    "iv_length",
    [8, 16],
)
class TestAEADOneShotSIV(_TestAEADOneShot):
    pass


@pytest.mark.parametrize(
    "mode",
    [modes.Modes.MODE_CCM],
)
@pytest.mark.parametrize(
    "key_length",
    _LENGTH_NORMAL,
)
@pytest.mark.parametrize(
    "iv_length",
    list(range(7, 14)),
)
class TestAEADOneShotCCM(_TestAEADOneShot):
    pass


@pytest.mark.parametrize(
    "mode",
    [modes.Modes.MODE_OCB],
)
@pytest.mark.parametrize(
    "key_length",
    _LENGTH_NORMAL,
)
@pytest.mark.parametrize(
    "iv_length",
    list(range(7, 16)),
)
class TestAEADOneShotOCB(_TestAEADOneShot):
    pass
