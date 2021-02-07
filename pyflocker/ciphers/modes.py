from enum import Enum


class Modes(Enum):
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
aead = frozenset(
    {
        Modes.MODE_GCM,
        Modes.MODE_CCM,
        Modes.MODE_EAX,
        Modes.MODE_OCB,
        Modes.MODE_SIV,
    }
)

# the special modes
special = frozenset(
    {
        Modes.MODE_SIV,
        Modes.MODE_CCM,
        Modes.MODE_OCB,
        # MODE_OPENPGP,
    }
)
