"""
Simple tests for AES

These tests are meant to check the API and hence, do not use
the official test vectors. The backends used by pyflocker
implements the tests using the required test vectors.
"""
import os

import pytest
from pyflocker.ciphers import AES, Modes, exc

_LENGTH_NORMAL = (16, 24, 32)
_LENGTH_SPECIAL_SIV = (32, 48, 64)


def _test_AES_base(*, key_lengths, iv, mode, authdata=None, **kwargs):
    # we need different IV sizes if we want to test all modes

    data = bytes(16)
    for key in map(os.urandom, key_lengths):
        enc = AES.new(True, key, mode, iv, **kwargs)
        dec = AES.new(False, key, mode, iv, **kwargs)
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


def _test_AES_nospecial_base(*, aead, hmac=False, authdata=None):
    data = bytes(16)

    if aead:
        modes = AES.aead ^ AES.special
        kwargs = dict()
    else:
        modes = set(Modes) ^ AES.aead
        kwargs = dict(hashed=hmac)

    for mode in modes:
        _test_AES_base(
            key_lengths=_LENGTH_NORMAL,
            iv=os.urandom(16),
            mode=mode,
            authdata=authdata,
            **kwargs,
        )


def test_AES_normal(**kwargs):
    _test_AES_nospecial_base(aead=False, **kwargs)


def test_AES_hmac_no_authdata():
    test_AES_normal(hmac=True)


def test_AES_hmac_authdata():
    test_AES_normal(hmac=True, authdata=os.urandom(32))


def test_AES_aead_no_authdata(**kwargs):
    _test_AES_nospecial_base(aead=True, **kwargs)


def test_AES_aead_authdata():
    test_AES_aead_no_authdata(authdata=os.urandom(32))


def test_AES_aead_special(authdata=None):
    for mode in AES.special:
        if mode == AES.MODE_SIV:
            klen = _LENGTH_SPECIAL_SIV
        else:
            klen = _LENGTH_NORMAL
        _test_AES_base(
            key_lengths=klen,
            iv=os.urandom(13),
            mode=mode,
            authdata=authdata,
        )


def test_AES_aead_special_authdata():
    test_AES_aead_special(os.urandom(32))
