from __future__ import annotations

import os
from itertools import product
from typing import TYPE_CHECKING

import pytest
from pyflocker import locker
from pyflocker.ciphers import modes
from pyflocker.ciphers.backends import Backends
from pyflocker.ciphers.exc import DecryptionError

if TYPE_CHECKING:
    from pathlib import Path

ENCRYPTION_DECRYPTION_DATA = b"ENCRYPTION_DECRYPTION_DATA for testing"
ENCRYPTION_DECRYPTION_PASSWORD = b"ENCRYPTION_DECRYPTION_PASSWORD for testing"
TESTING_METADATA = b"TESTING_METADATA"
TESTING_EXT = ".testing"


@pytest.mark.parametrize(
    "backend1, backend2",
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize("mode", sorted(set(modes.Modes) ^ modes.SPECIAL))
class TestLocker:
    @pytest.mark.parametrize("dklen", [16, 24, 32, 128, 192, 256])
    def test_encryptf_decryptf(
        self,
        mode,
        backend1,
        backend2,
        dklen,
        tmp_path: Path,
    ):
        infile_path = tmp_path / "infile"
        outfile_path = tmp_path / "outfile"
        decrypted_file_path = tmp_path / "decrypted_file"

        infile_path.write_bytes(ENCRYPTION_DECRYPTION_DATA)

        with (
            infile_path.open("rb") as infile,
            outfile_path.open("w+b") as outfile,
            decrypted_file_path.open("w+b") as decrypted_file,
        ):
            # encrypt data
            locker.encryptf(
                infile,
                outfile,
                ENCRYPTION_DECRYPTION_PASSWORD,
                backend=backend1,
                aes_mode=mode,
                dklen=dklen,
            )

            # rewind back to the start
            outfile.seek(0)

            # decrypt data
            locker.decryptf(
                outfile,
                decrypted_file,
                ENCRYPTION_DECRYPTION_PASSWORD,
                backend=backend2,
                dklen=dklen,
            )

            # rewind the original file and decrypted file to the beginning
            decrypted_file.seek(0)
            infile.seek(0)

        assert (
            decrypted_file_path.read_bytes()
            == infile_path.read_bytes()
            == ENCRYPTION_DECRYPTION_DATA
        )

    def test_encrypt_decrypt(self, mode, backend1, backend2, tmp_path: Path):
        infile_path = tmp_path / "infile"
        outfile_path = tmp_path / "outfile"
        decrypted_file_path = tmp_path / "decrypted_file"

        infile_path.write_bytes(ENCRYPTION_DECRYPTION_DATA)

        locker.encrypt(
            infile_path,
            outfile_path,
            ENCRYPTION_DECRYPTION_PASSWORD,
            backend=backend1,
            aes_mode=mode,
            remove=False,
        )

        locker.decrypt(
            outfile_path,
            decrypted_file_path,
            ENCRYPTION_DECRYPTION_PASSWORD,
            backend=backend2,
            remove=False,
        )

        assert (
            decrypted_file_path.read_bytes()
            == infile_path.read_bytes()
            == ENCRYPTION_DECRYPTION_DATA
        )

    def test_lockerf(self, mode, backend1, backend2, tmp_path: Path):
        infile_path = tmp_path / "infile"
        outfile_path = tmp_path / "outfile"
        decrypted_file_path = tmp_path / "decrypted_file"

        infile_path.write_bytes(ENCRYPTION_DECRYPTION_DATA)

        with (
            infile_path.open("rb") as infile,
            outfile_path.open("w+b") as outfile,
            decrypted_file_path.open("w+b") as decrypted_file,
        ):
            locker.lockerf(
                infile,
                outfile,
                ENCRYPTION_DECRYPTION_PASSWORD,
                True,
                backend=backend1,
                aes_mode=mode,
            )

            outfile.seek(0)

            locker.lockerf(
                outfile,
                decrypted_file,
                ENCRYPTION_DECRYPTION_PASSWORD,
                False,
                backend=backend2,
                aes_mode=mode,
            )

        assert (
            decrypted_file_path.read_bytes()
            == infile_path.read_bytes()
            == ENCRYPTION_DECRYPTION_DATA
        )

    def test_locker_newfile(self, mode, backend1, backend2, tmp_path: Path):
        infile_path = tmp_path / "infile"
        outfile_path = tmp_path / "outfile"
        decrypted_file_path = tmp_path / "decrypted_file"

        infile_path.write_bytes(ENCRYPTION_DECRYPTION_DATA)

        locker.locker(
            infile_path,
            ENCRYPTION_DECRYPTION_PASSWORD,
            True,
            newfile=outfile_path,
            backend=backend1,
            aes_mode=mode,
            remove=False,
        )

        locker.locker(
            outfile_path,
            ENCRYPTION_DECRYPTION_PASSWORD,
            False,
            newfile=decrypted_file_path,
            backend=backend2,
            remove=False,
        )

        assert (
            decrypted_file_path.read_bytes()
            == infile_path.read_bytes()
            == ENCRYPTION_DECRYPTION_DATA
        )


def test_locker_auto_newfile_auto_encrypting(tmp_path: Path):
    infile_path = tmp_path / "infile"
    infile_path.write_bytes(ENCRYPTION_DECRYPTION_DATA)

    locker.locker(
        infile_path,
        ENCRYPTION_DECRYPTION_PASSWORD,
        ext=TESTING_EXT,
    )

    outfile_path = infile_path.with_suffix(TESTING_EXT)
    assert os.path.exists(outfile_path)
    assert not os.path.exists(infile_path)

    locker.locker(
        outfile_path,
        ENCRYPTION_DECRYPTION_PASSWORD,
        ext=TESTING_EXT,
    )

    assert os.path.exists(infile_path)
    # outfile is gone; infile remains
    assert not os.path.exists(outfile_path)


def test_extract_header_from_file(tmp_path: Path):
    infile_path = tmp_path / "infile"
    outfile_path = tmp_path / "outfile"

    infile_path.write_bytes(ENCRYPTION_DECRYPTION_DATA)

    locker.encrypt(
        infile_path,
        outfile_path,
        ENCRYPTION_DECRYPTION_PASSWORD,
        metadata=TESTING_METADATA,
        remove=False,
    )

    header = locker.extract_header_from_file(
        outfile_path,
        TESTING_METADATA,
    )
    assert header.metadata == TESTING_METADATA
    assert header.magic == locker.MAGIC


class TestLockerErrors:
    def test_encryptf_decryptf_unique_files_only(self, tmp_path: Path):
        file_path = tmp_path / "file"

        with file_path.open("w+b") as file:
            with pytest.raises(ValueError):
                locker.encryptf(file, file, ENCRYPTION_DECRYPTION_PASSWORD)

            with pytest.raises(ValueError):
                locker.decryptf(file, file, ENCRYPTION_DECRYPTION_PASSWORD)

    @pytest.mark.parametrize("mode", sorted(modes.SPECIAL))
    def test_encryptf_decryptf_mode_special_error(
        self,
        mode,
        tmp_path: Path,
    ):
        infile_path = tmp_path / "infile"
        outfile_path = tmp_path / "outfile_path"

        with (
            infile_path.open("w+b") as infile,
            outfile_path.open("w+b") as outfile,
            pytest.raises(NotImplementedError),
        ):
            locker.encryptf(
                infile,
                outfile,
                ENCRYPTION_DECRYPTION_PASSWORD,
                aes_mode=mode,
            )

    def test_encryptf_max_metadata_len(self, tmp_path: Path):
        infile_path = tmp_path / "infile"
        outfile_path = tmp_path / "outfile_path"

        with (
            infile_path.open("w+b") as infile,
            outfile_path.open("w+b") as outfile,
            pytest.raises(OverflowError),
        ):
            locker.encryptf(
                infile,
                outfile,
                ENCRYPTION_DECRYPTION_PASSWORD,
                metadata=bytes(locker.MAX_METADATA_LEN + 1),
            )

    def test_locker_newfile_ext_exculsive(self, tmp_path: Path):
        nonexistent_path = tmp_path / "nonexistent"
        with pytest.raises(ValueError):
            locker.locker(
                nonexistent_path,
                ENCRYPTION_DECRYPTION_PASSWORD,
                newfile="newfile",
                ext="ext",
            )

    def test_header_validation(self, tmp_path: Path):
        infile_path = tmp_path / "infile"
        outfile_path = tmp_path / "outfile"
        decrypted_file_path = tmp_path / "decrypted_file"

        infile_path.write_bytes(ENCRYPTION_DECRYPTION_DATA)

        with (
            infile_path.open("rb") as infile,
            outfile_path.open("w+b") as outfile,
            decrypted_file_path.open("w+b") as decrypted_file,
        ):
            locker.encryptf(
                infile,
                outfile,
                ENCRYPTION_DECRYPTION_DATA,
            )

            with pytest.raises(TypeError):
                locker.decryptf(
                    decrypted_file,
                    outfile,
                    ENCRYPTION_DECRYPTION_DATA,
                )

    def test_header_validation_metadata_mismatch(self, tmp_path: Path):
        infile_path = tmp_path / "infile"
        outfile_path = tmp_path / "outfile"
        decrypted_file_path = tmp_path / "decrypted_file"

        infile_path.write_bytes(ENCRYPTION_DECRYPTION_DATA)

        with (
            infile_path.open("rb") as infile,
            outfile_path.open("w+b") as outfile,
            decrypted_file_path.open("w+b") as decrypted_file,
        ):
            locker.encryptf(
                infile,
                outfile,
                ENCRYPTION_DECRYPTION_DATA,
                metadata=TESTING_METADATA,
            )

            outfile.seek(0)

            with pytest.raises(TypeError):
                locker.decryptf(
                    outfile,
                    decrypted_file,
                    ENCRYPTION_DECRYPTION_DATA,
                    metadata=b"not TESTING_METADATA",
                )

    def test_incorrect_dklen(self, tmp_path: Path):
        infile_path = tmp_path / "infile"
        outfile_path = tmp_path / "outfile"
        with (
            infile_path.open("wb") as infile,
            outfile_path.open("w+b") as outfile,
            pytest.raises(ValueError),
        ):
            locker.encryptf(
                infile,
                outfile,
                ENCRYPTION_DECRYPTION_PASSWORD,
                dklen=11,
            )

    def test_encrypt_decrypt_outfile_deleted_on_header_mismatch(
        self,
        tmp_path: Path,
    ):
        infile_path = tmp_path / "infile"
        outfile_path = tmp_path / "outfile"
        other_file_path = tmp_path / "other_file"

        infile_path.write_bytes(ENCRYPTION_DECRYPTION_DATA)

        locker.encrypt(
            infile_path,
            outfile_path,
            ENCRYPTION_DECRYPTION_PASSWORD,
        )
        assert not os.path.exists(infile_path)

        other_file_path.touch()
        # other_file_path is an empty file, causes header mismatch
        with pytest.raises(TypeError):
            locker.decrypt(
                other_file_path,
                infile_path,
                ENCRYPTION_DECRYPTION_PASSWORD,
            )
        assert not os.path.exists(infile_path)

    def test_encrypt_decrypt_outfile_deleted_on_decryption_error(
        self,
        tmp_path: Path,
    ):
        infile_path = tmp_path / "infile"
        outfile_path = tmp_path / "outfile"
        other_file_path = tmp_path / "other_file"

        infile_path.write_bytes(ENCRYPTION_DECRYPTION_DATA)

        locker.encrypt(
            infile_path,
            outfile_path,
            ENCRYPTION_DECRYPTION_PASSWORD,
        )
        assert not os.path.exists(infile_path)

        with pytest.raises(DecryptionError):
            locker.decrypt(
                outfile_path,
                other_file_path,
                b"not ENCRYPTION_DECRYPTION_PASSWORD",
            )
        assert os.path.exists(outfile_path)
        assert not os.path.exists(other_file_path)
