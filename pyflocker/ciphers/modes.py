from enum import Enum


class Modes(Enum):
    """All modes supported by pyflocker and various ciphers."""

    MODE_GCM = "GCM"
    MODE_CTR = "CTR"
    # MODE_CBC = "CBC"
    MODE_CFB = "CFB"
    MODE_CFB8 = "CFB8"
    MODE_OFB = "OFB"
    # MODE_OPENPGP = "OPENPGP"
    MODE_CCM = "CCM"
    MODE_EAX = "EAX"
    MODE_SIV = "SIV"
    MODE_OCB = "OCB"


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
