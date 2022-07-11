from __future__ import annotations

from enum import IntEnum


class Modes(IntEnum):
    """Modes for symmetric ciphers (eg. AES, Camellia)."""

    MODE_GCM = 1
    MODE_CTR = 2
    MODE_CFB = 3
    MODE_CFB8 = 4
    MODE_OFB = 5
    MODE_CCM = 6
    MODE_EAX = 7
    MODE_SIV = 8
    MODE_OCB = 9
    # MODE_CBC = ...
    # MODE_OPENPGP = ...


# authenticated modes
AEAD = frozenset(
    {
        Modes.MODE_GCM,
        Modes.MODE_CCM,
        Modes.MODE_EAX,
        Modes.MODE_OCB,
        Modes.MODE_SIV,
    }
)

aead = AEAD

#: the special modes
SPECIAL = frozenset(
    {
        Modes.MODE_SIV,
        Modes.MODE_CCM,
        Modes.MODE_OCB,
        # MODE_OPENPGP,
    }
)

special = SPECIAL
