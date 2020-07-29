from collections import namedtuple
from ..interfaces import Hash

MGF1 = namedtuple(
    'MGF1',
    'hash',
    defaults=[Hash.new('sha256')],
)

OAEP = namedtuple(
    'OAEP',
    'mgf, hash, label',
    defaults=[MGF1(), Hash.new('sha256'), None],
)

PSS = namedtuple(
    'PSS',
    'mgf, salt_len',
    defaults=[MGF1(), None],
)
