from __future__ import annotations

import io

import pytest

from pyflocker.ciphers import exc
from pyflocker.ciphers.backends import symmetric
from pyflocker.ciphers.interfaces import AES


def get_file_encryptor():
    file = io.BytesIO(b"somedata")
    cipher = AES.new(True, bytes(32), AES.MODE_GCM, bytes(12), file=file)
    assert isinstance(cipher, symmetric.FileCipherWrapper)
    return cipher


class TestFileCipherWrapper:
    def test_error_if_cipher_is_not_symmetric(self):
        class FakeType:
            pass

        with pytest.raises(TypeError):
            symmetric.FileCipherWrapper(FakeType(), None)  # type: ignore


class TestHMACWrapper:
    def test_error_if_cipher_is_not_symmetric(self):
        class FakeType:
            pass

        with pytest.raises(TypeError):
            symmetric.HMACWrapper(FakeType(), b"", b"")


class TestErrors:
    def test_error_on_authenticate_after_finalize(self):
        cipher = get_file_encryptor()
        cipher.finalize()
        with pytest.raises(exc.AlreadyFinalized):
            cipher.authenticate(b"AS")

    def test_error_on_update_and_update_into_after_finalize(self):
        cipher = get_file_encryptor()
        cipher.finalize()
        with pytest.raises(exc.AlreadyFinalized):
            cipher.update()

        out = io.BytesIO()
        with pytest.raises(exc.AlreadyFinalized):
            cipher.update_into(out)

    def test_error_on_calculate_tag_before_finalize(self):
        cipher = get_file_encryptor()
        with pytest.raises(exc.NotFinalized):
            cipher.calculate_tag()

    def test_error_on_finalize_after_finalize(self):
        cipher = get_file_encryptor()
        cipher.finalize()
        with pytest.raises(exc.AlreadyFinalized):
            cipher.finalize()

    def test_error_on_update_into_if_decrypting_and_tag_unsupplied(self):
        file = io.BytesIO(b"somedata")
        cipher = AES.new(False, bytes(32), AES.MODE_GCM, bytes(12), file=file)
        assert isinstance(cipher, symmetric.FileCipherWrapper)

        out = io.BytesIO()
        with pytest.raises(ValueError, match="tag is required"):
            cipher.update_into(out)
