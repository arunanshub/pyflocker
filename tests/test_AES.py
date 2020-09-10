"""
Simple tests for AES

These tests are meant to check the API and hence, do not use
the official test vectors. The backends used by pyflocker
implements the tests using the required test vectors.
"""
import os
import io

import pytest
from pyflocker.ciphers import AES, Modes, exc, Backends

_LENGTH_NORMAL = (16, 24, 32)
_LENGTH_SPECIAL_SIV = (32, 48, 64)


@pytest.fixture(params=list(Backends))
def backend(request):
    return request.param


def _test_AES_base(*, key, iv, mode, backend, authdata=None, **kwargs):
    # we need different IV sizes if we want to test all modes

    data = bytes(16)
    try:
        enc = AES.new(True, key, mode, iv, backend=backend, **kwargs)
        dec = AES.new(False, key, mode, iv, backend=backend, **kwargs)
    except NotImplementedError:
        pytest.skip(f"unsupported mode: {mode} for {backend}.")
    if authdata is not None:
        enc.authenticate(authdata)
        dec.authenticate(authdata)

    try:
        # check encryption-decryption
        if mode not in AES.special:
            assert dec.update(enc.update(data)) == data
        else:
            dec.update(enc.update(data), enc.calculate_tag()) == data
    except exc.DecryptionError:
        pytest.fail('Authentication check failed')

    finally:
        if mode not in AES.special:
            enc.finalize()
            if kwargs.get('hashed') or mode in AES.aead:
                try:
                    dec.finalize(enc.calculate_tag())
                except exc.DecryptionError:
                    pytest.fail('Authentication check failed')


@pytest.mark.parametrize('key', map(os.urandom, _LENGTH_NORMAL))
@pytest.mark.parametrize('mode', set(Modes) ^ AES.aead)
def test_AES_normal(key, mode, backend, **kwargs):
    _test_AES_base(
        key=key,
        mode=mode,
        iv=os.urandom(16),
        backend=backend,
        **kwargs,
    )


@pytest.mark.parametrize('key', map(os.urandom, _LENGTH_NORMAL))
@pytest.mark.parametrize('mode', set(Modes) ^ AES.aead)
def test_AES_hmac_no_authdata(key, mode, backend):
    test_AES_normal(
        key=key,
        mode=mode,
        backend=backend,
        hashed=True,
    )


@pytest.mark.parametrize('key', map(os.urandom, _LENGTH_NORMAL))
@pytest.mark.parametrize('mode', set(Modes) ^ AES.aead)
def test_AES_hmac_authdata(key, mode, backend):
    test_AES_normal(
        key=key,
        mode=mode,
        hashed=True,
        authdata=os.urandom(32),
        backend=backend,
    )


@pytest.mark.parametrize('key', map(os.urandom, _LENGTH_NORMAL))
@pytest.mark.parametrize('mode', AES.aead ^ AES.special)
def test_AES_aead_no_authdata(key, mode, backend, iv=None, **kwargs):
    _test_AES_base(
        key=key,
        mode=mode,
        iv=iv or os.urandom(16),
        backend=backend,
        **kwargs,
    )


@pytest.mark.parametrize('key', map(os.urandom, _LENGTH_NORMAL))
@pytest.mark.parametrize('mode', AES.aead ^ AES.special)
def test_AES_aead_authdata(key, mode, backend):
    test_AES_aead_no_authdata(key, mode, backend, authdata=os.urandom(32))


@pytest.mark.parametrize('mode', AES.special)
def test_AES_aead_special(mode, backend, authdata=None):
    if mode == AES.MODE_SIV:
        klen = _LENGTH_SPECIAL_SIV
    else:
        klen = _LENGTH_NORMAL
    for key in map(os.urandom, klen):
        test_AES_aead_no_authdata(key, mode, backend, iv=os.urandom(13))


@pytest.mark.parametrize('mode', AES.special)
def test_AES_aead_special_authdata(mode, backend):
    test_AES_aead_special(mode, backend, os.urandom(32))


def test_AES_file_buffer():
    modes = set(Modes) ^ AES.special

    for key in map(os.urandom, _LENGTH_NORMAL):
        for mode in modes:
            f1 = io.BytesIO(bytes(16384))
            f2 = io.BytesIO()
            f3 = io.BytesIO()

            iv = os.urandom(16)
            enc = AES.new(True, key, mode, iv, file=f1)
            dec = AES.new(False, key, mode, iv, file=f2)
            enc.update_into(f2, blocksize=1024)

            f1.seek(0)
            f2.seek(0)
            try:
                dec.update_into(f3, enc.calculate_tag(), blocksize=1024)
            except exc.DecryptionError:
                pytest.fail('Authentication check failed')
            f3.seek(0)
            assert f1.getvalue() == f3.getvalue()


@pytest.mark.parametrize('key', map(os.urandom, _LENGTH_NORMAL))
@pytest.mark.parametrize('mode', set(Modes) ^ AES.special)
def test_AES_databuffer(key, mode, backend):
    iv = os.urandom(16)

    rbuf = memoryview(bytearray(16384))
    if backend == Backends.CRYPTOGRAPHY:
        wbuf = memoryview(bytearray(16384 + 15))
        test = memoryview(bytearray(16384 + 15))
    else:
        wbuf = memoryview(bytearray(16384))
        test = memoryview(bytearray(16384))

    kwargs = {}
    if mode not in AES.aead:
        kwargs = dict(hashed=True)
    enc = AES.new(True, key, mode, iv, backend=backend, **kwargs)
    dec = AES.new(False, key, mode, iv, backend=backend, **kwargs)
    enc.update_into(rbuf, wbuf)

    if backend == Backends.CRYPTOGRAPHY:
        dec.update_into(wbuf[:-15], test)
    else:
        dec.update_into(wbuf, test)
    enc.finalize()

    if backend == Backends.CRYPTOGRAPHY:
        assert rbuf.tobytes() == test[:-15].tobytes()
    else:
        assert rbuf.tobytes() == test.tobytes()

    try:
        dec.finalize(enc.calculate_tag())
    except exc.DecryptionError:
        pytest.fail('Authentication check failed')
