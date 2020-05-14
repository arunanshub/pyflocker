from enum import Enum


# define all modes
class Modes(Enum):
    """All modes supported by pyflocker and various ciphers."""

    MODE_GCM = "MODE_GCM"
    MODE_CTR = "MODE_CTR"
    # MODE_CBC = "MODE_CBC"
    MODE_CFB = "MODE_CFB"
    MODE_OFB = "MODE_OFB"
    # MODE_OPENPGP = "MODE_OPENPGP"
    MODE_CCM = "MODE_CCM"
    MODE_EAX = "MODE_EAX"
    MODE_SIV = "MODE_SIV"
    MODE_OCB = "MODE_OCB"


# authenticated modes
aead = {
    Modes.MODE_GCM,
    Modes.MODE_CCM,
    Modes.MODE_EAX,
    Modes.MODE_OCB,
    Modes.MODE_SIV,
}


# the special modes
special = {
    Modes.MODE_SIV,
    Modes.MODE_CCM,
    Modes.MODE_OCB,
    # MODE_OPENPGP,
}

