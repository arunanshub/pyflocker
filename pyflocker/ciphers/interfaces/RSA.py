from .. import load_cipher as _load_cpr


def _load_rsa_cpr(backend):
    return _load_cpr('RSA', backend)


def generate(bits, e=65537, *, backend=None):
    return _load_rsa_cpr(backend).RSAPrivateKey(bits, e)


def load_public_key(data, *, backend=None):
    # differentiate between public and private key
    return _load_rsa_cpr(backend).RSAPublicKey.load(data)


def load_private_key(data, passphrase=None, *, backend=None):
    return _load_rsa_cpr(backend).RSAPrivateKey.load(data, passphrase)
