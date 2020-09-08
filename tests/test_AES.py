"""
Simple tests for AES

These tests are meant to check the API and hence, do not use
the official test vectors. The backends used by pyflocker
implements the tests using the required test vectors.
"""
import os

import pytest
from pyflocker.ciphers import AES, Modes, exc


def _test_AES_nospecial_base(*, aead, hmac=False, authdata=None):
    data = bytes(16)

    if aead:
        modes = AES.aead ^ AES.special
        kwargs = dict()
    else:
        modes = set(Modes) ^ AES.aead
        kwargs = dict(hashed=hmac)

    for key in map(os.urandom, (16, 24, 32)):
        iv = os.urandom(16)  # each key will have its own iv
        for mode in modes:
            enc = AES.new(True, key, mode, iv, **kwargs)
            dec = AES.new(False, key, mode, iv, **kwargs)
            if authdata is not None:
                enc.authenticate(authdata)
                dec.authenticate(authdata)

            try:
                # check encryption-decryption
                assert dec.update(enc.update(data)) == data
            finally:
                enc.finalize()
                if hmac or aead:
                    try:
                        dec.finalize(enc.calculate_tag())
                    except exc.DecryptionError:
                        pytest.fail('Authentication check failed')


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
