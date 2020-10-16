import os
import pytest
from pyflocker import Backends
from pyflocker.ciphers import exc


def _create_buffer(length, extend, backend):
    if backend == Backends.CRYPTOGRAPHY:
        buf = memoryview(bytearray(length + (extend or 0)))
        return buf
    return memoryview(bytearray(length))


class BaseSymmetric:
    def test_update_into(self, cipher, backend1, backend2, *, extend=15):
        rbuf = memoryview(bytearray(16384))

        enc = cipher(True, backend=backend1)
        dec = cipher(False, backend=backend2)

        wbuf = _create_buffer(len(rbuf), extend, backend1)
        test = _create_buffer(len(rbuf), extend, backend2)

        enc.update_into(rbuf, wbuf)
        enc.finalize()

        if extend is not None:
            wbuf = wbuf[
                : (-extend if backend1 == Backends.CRYPTOGRAPHY else None)
            ]

        dec.update_into(wbuf, test)
        try:
            dec.finalize(enc.calculate_tag())
        except NotImplementedError:
            assert enc._auth is None

        if extend is not None:
            test = test[
                : (-extend if backend2 == Backends.CRYPTOGRAPHY else None)
            ]

        assert test.tobytes() == rbuf.tobytes()

    def test_update(self, cipher, backend1, backend2):
        enc = cipher(True, backend=backend1)
        dec = cipher(False, backend=backend2)

        data = bytes(32)
        assert dec.update(enc.update(data)) == data

    def test_write_into_file_buffer(self, cipher, backend1, backend2):
        import io

        f1 = io.BytesIO(bytes(16384))
        f2 = io.BytesIO()
        f3 = io.BytesIO()
        try:
            enc = cipher(True, file=f1, backend=backend1)
            dec = cipher(False, file=f2, backend=backend2)
        except TypeError:
            # some ciphers don't require mode -- ChaCha20
            mode = cipher.keywords.get("mode") or cipher
            pytest.skip(
                f"{mode} does not support writing into file-like objects"
            )

        enc.update_into(f2, blocksize=1024)
        f2.seek(0)

        try:
            dec.update_into(f3, blocksize=2048, tag=enc.calculate_tag())
        except exc.DecryptionError:
            pytest.fail("Authentication check failed")

        assert f3.getvalue() == f1.getvalue()
