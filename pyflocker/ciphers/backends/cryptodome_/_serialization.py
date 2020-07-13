"""Constants necessary for Key serialization."""

# required for limiting invalid interactions
encodings = {
    'PEM': 'PEM',
    'DER': 'DER',
    'OpenSSH': 'OpenSSH',
}

formats = {
    'PKCS1': 1,
    'PKCS8': 8,
}

# PKCS#8 password derivation mechanisms
protection_schemes = frozenset((
    'PBKDF2WithHMAC-SHA1AndAES128-CBC',
    'PBKDF2WithHMAC-SHA1AndAES192-CBC',
    'PBKDF2WithHMAC-SHA1AndAES256-CBC',
    'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
    'scryptAndAES128-CBC',
    'scryptAndAES192-CBC',
    'scryptAndAES256-CBC',
))
