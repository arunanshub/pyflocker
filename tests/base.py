import io

import pytest

from pyflocker.ciphers import exc
from pyflocker.ciphers.backends import Backends


def _create_buffer(length, offset, backend):
    if backend == Backends.CRYPTOGRAPHY:
        return memoryview(bytearray(length + offset))
    return memoryview(bytearray(length))


class BaseSymmetric:
    @staticmethod
    def _get_cipher(cipher, backend1, backend2):
        try:
            enc = cipher(encrypting=True, backend=backend1)
        except exc.UnsupportedAlgorithm:
            pytest.skip(f"Unsupported by {backend1}")

        try:
            dec = cipher(encrypting=False, backend=backend2)
        except exc.UnsupportedAlgorithm:
            pytest.skip(f"Unsupported by {backend2}")
        return enc, dec

    @staticmethod
    def _test_finalize(enc, dec):
        for i in enc, dec:
            with pytest.raises(exc.AlreadyFinalized):
                i.finalize()

    @staticmethod
    def _finalizer(enc, dec):
        enc.finalize(), dec.finalize()

    def test_update(self, cipher, backend1, backend2):
        enc, dec = self._get_cipher(cipher, backend1, backend2)
        data = bytes(64)
        ctxt = enc.update(data)
        ptxt = dec.update(ctxt)
        self._finalizer(enc, dec)
        assert data == ptxt
        self._test_finalize(enc, dec)

    def test_update_into(self, cipher, backend1, backend2, *, offset):
        # offset value is specified by the subclass
        enc, dec = self._get_cipher(cipher, backend1, backend2)
        readbuf = memoryview(bytearray(64))
        in_ = _create_buffer(64, offset, backend1)
        out = _create_buffer(64, offset, backend2)

        try:
            enc.update_into(readbuf, in_)
        except NotImplementedError:
            pytest.skip(f"update_into not supported by {enc}")
        try:
            dec.update_into(in_[: len(readbuf)], out)
        except NotImplementedError:
            pytest.skip(f"update_into not supported by {dec}")
        self._finalizer(enc, dec)

        assert out.tobytes()[: len(readbuf)] == readbuf.tobytes()
        self._test_finalize(enc, dec)


class BaseSymmetricAEAD(BaseSymmetric):
    @staticmethod
    def _finalizer(enc, dec):
        enc.finalize()
        dec.finalize(enc.calculate_tag())

    def test_update_with_auth(self, cipher, backend1, backend2):
        enc, dec = self._get_cipher(cipher, backend1, backend2)

        auth, data = bytes(64), bytes(64)

        enc.authenticate(auth)
        dec.authenticate(auth)

        ctxt = enc.update(data)
        ptxt = dec.update(ctxt)

        self._finalizer(enc, dec)
        assert data == ptxt
        self._test_finalize(enc, dec)

    def test_update_into_with_auth(
        self,
        cipher,
        backend1,
        backend2,
        *,
        offset,
    ):
        # offset value is specified by the subclass
        enc, dec = self._get_cipher(cipher, backend1, backend2)
        auth = bytes(64)
        enc.authenticate(auth)
        dec.authenticate(auth)

        readbuf = memoryview(bytearray(64))
        in_ = _create_buffer(64, offset, backend1)
        out = _create_buffer(64, offset, backend2)

        try:
            enc.update_into(readbuf, in_)
        except NotImplementedError:
            pytest.skip(f"update_into not supported by {enc}")
        try:
            dec.update_into(in_[: len(readbuf)], out)
        except NotImplementedError:
            pytest.skip(f"update_into not supported by {dec}")

        self._finalizer(enc, dec)
        assert out.tobytes()[: len(readbuf)] == readbuf.tobytes()
        self._test_finalize(enc, dec)

    def test_update_into_file_buffer(self, cipher, backend1, backend2):
        read = io.BytesIO(bytes(16384))
        in_ = io.BytesIO()
        out = io.BytesIO()
        auth = bytes(64)

        try:
            enc = cipher(encrypting=True, file=read, backend=backend1)
        except exc.UnsupportedAlgorithm:
            pytest.skip(f"Unsupported by {backend1}")

        enc.authenticate(auth)
        enc.update_into(in_, blocksize=1024)
        in_.seek(0)

        try:
            dec = cipher(encrypting=False, file=in_, backend=backend2)
        except exc.UnsupportedAlgorithm:
            pytest.skip(f"Unsupported by {backend2}")

        dec.authenticate(auth)
        dec.update_into(out, blocksize=1024, tag=enc.calculate_tag())

        assert read.getvalue() == out.getvalue()
