# check for Crypto(dome)
try:
    import Cryptodome
except ModuleNotFoundError:
    import Crypto
    if int(Crypto.__version__[0]) < 3:
        raise
