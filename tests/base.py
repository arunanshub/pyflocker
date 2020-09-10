import os
import pytest
from pyflocker import Backends


class SymBase:
    def test_update_into(self, cipher, backend):
        rbuf = memoryview(bytearray(16384))

        if backend == Backends.CRYPTOGRAPHY:
            wbuf = memoryview(bytearray(16384 + 15))
            test = memoryview(bytearray(16384 + 15))
        else:
            wbuf = memoryview(bytearray(16384))
            test = memoryview(bytearray(16384))

        try:
            enc = cipher(True, backend=backend)
            dec = cipher(False, backend=backend)
        except NotImplementedError:
            pytest.skip(f"Unsupported by backend {backend}")

        enc.update_into(rbuf, wbuf)
        if backend == Backends.CRYPTOGRAPHY:
            dec.update_into(wbuf[:-15], test)
            assert rbuf.tobytes() == test[:-15].tobytes()
        else:
            dec.update_into(wbuf, test)
            assert rbuf.tobytes() == test.tobytes()

    def test_update(self, key, cipher, backend):
        try:
            enc = cipher(True, backend=backend)
            dec = cipher(False, backend=backend)
        except NotImplementedError:
            pytest.skip(f"Unsupported by backend {backend}")

        data = bytes(32)
        assert dec.update(enc.update(data)) == data
