from collections import namedtuple

MGF1 = namedtuple(
    'MGF1',
    'hash',
    defaults=['sha256'],
)

OAEP = namedtuple(
    'OAEP',
    'mgf, hash, label',
    defaults=[MGF1(), 'sha256', None],
)

PSS = namedtuple(
    'PSS',
    'mgf, salt_len',
    defaults=[MGF1(), None],
)
