import os
from contextlib import contextmanager
from itertools import combinations_with_replacement
from tempfile import TemporaryDirectory, TemporaryFile

import pytest

from pyflocker import locker
from pyflocker.ciphers import exc, modes
from pyflocker.ciphers.backends import Backends


@contextmanager
def tempfiles():
    try:
        fs = [TemporaryFile() for i in range(3)]
        yield fs
    finally:
        [f.close() for f in fs]


@pytest.mark.parametrize(
    "backend1, backend2", list(combinations_with_replacement(Backends, 2))
)
class TestLocker:
    @pytest.mark.parametrize(
        "mode",
        set(modes.Modes) ^ modes.special,
    )
    @pytest.mark.parametrize(
        "chkfail",
        [False, True],
    )
    def test_enc_dec(self, backend1, backend2, mode, chkfail):
        data = bytes(1239)
        password = os.urandom(23).hex().encode()

        with tempfiles() as (f1, f2, f3):
            f1.write(data)
            f1.seek(0)

            locker.lockerf(
                f1, f2, password, True, aes_mode=mode, backend=backend1
            )

            f2.seek(0)

            if not chkfail:
                locker.lockerf(
                    f2, f3, password, False, aes_mode=mode, backend=backend2
                )
                return

            password = os.urandom(23).hex().encode()
            with pytest.raises(exc.DecryptionError):
                locker.lockerf(
                    f2, f3, password, False, aes_mode=mode, backend=backend2
                )

    @pytest.mark.parametrize(
        "mode",
        set(modes.Modes) ^ modes.special,
    )
    @pytest.mark.parametrize(
        "chkfail",
        [False, True],
    )
    def test_enc_dec_named(self, backend1, backend2, mode, chkfail):
        data = bytes(1439)
        password = os.urandom(23).hex().encode()
        with TemporaryDirectory() as tmp:
            # write and keep
            file1 = os.path.join(tmp, os.urandom(6).hex())
            # this must not be present in path
            file2 = os.path.join(tmp, os.urandom(6).hex())

            with open(file1, "wb") as f1:
                f1.write(data)
            del f1

            # encryption: file2 gets created here
            locker.locker(
                file1,
                password,
                True,
                newfile=file2,
                aes_mode=mode,
                backend=backend1,
            )

            file3 = os.path.join(tmp, os.urandom(6).hex())

            if not chkfail:
                locker.locker(
                    file2,
                    password,
                    False,
                    newfile=file3,
                    aes_mode=mode,
                    backend=backend2,
                )
                return

            password = os.urandom(23).hex().encode()
            with pytest.raises(exc.DecryptionError):
                locker.locker(
                    file2,
                    password,
                    False,
                    newfile=file3,
                    aes_mode=mode,
                    backend=backend2,
                )
