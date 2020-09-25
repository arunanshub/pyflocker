import os
import pytest
from pyflocker import Backends
from pyflocker.ciphers import exc


class BaseSymmetric:
    def test_update_into(self, cipher, backend):
        rbuf = memoryview(bytearray(16384))

        if backend == Backends.CRYPTOGRAPHY:
            wbuf = memoryview(bytearray(16384 + 15))
            test = memoryview(bytearray(16384 + 15))
        else:
            wbuf = memoryview(bytearray(16384))
            test = memoryview(bytearray(16384))

        enc = cipher(True, backend=backend)
        dec = cipher(False, backend=backend)

        enc.update_into(rbuf, wbuf)
        if backend == Backends.CRYPTOGRAPHY:
            dec.update_into(wbuf[:-15], test)
            assert rbuf.tobytes() == test[:-15].tobytes()
        else:
            dec.update_into(wbuf, test)
            assert rbuf.tobytes() == test.tobytes()

    def test_update(self, cipher, backend):
        enc = cipher(True, backend=backend)
        dec = cipher(False, backend=backend)

        data = bytes(32)
        assert dec.update(enc.update(data)) == data

    def test_write_into_file_buffer(self, cipher, backend):
        import io
        f1 = io.BytesIO(bytes(16384))
        f2 = io.BytesIO()
        f3 = io.BytesIO()
        try:
            enc = cipher(True, file=f1, backend=backend)
            dec = cipher(False, file=f2, backend=backend)
        except TypeError:
            pytest.skip(
                "Cipher does not support writing into file-like objects")

        enc.update_into(f2, blocksize=1024)
        f2.seek(0)

        try:
            dec.update_into(f3, blocksize=2048, tag=enc.calculate_tag())
        except exc.DecryptionError:
            pytest.fail("Authentication check failed")

        assert f3.getvalue() == f1.getvalue()
