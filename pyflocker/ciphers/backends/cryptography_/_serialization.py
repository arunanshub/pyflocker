from cryptography.hazmat.primitives import serialization as ser

encodings = {
    'PEM': ser.Encoding.PEM,
    'DER': ser.Encoding.DER,
    'OpenSSH': ser.Encoding.OpenSSH,
    'Raw': ser.Encoding.Raw,
    'X962': ser.Encoding.X962,
}

private_format = {
    'PKCS8': ser.PrivateFormat.PKCS8,
    'TraditionalOpenSSL': ser.PrivateFormat.TraditionalOpenSSL,
    'Raw': ser.PrivateFormat.Raw,
    'PKCS1': ser.PrivateFormat.TraditionalOpenSSL,  # compat with Cryptodome
}

try:
    private_format['OpenSSH'] = ser.PrivateFormat.OpenSSH
except AttributeError:
    pass

public_format = {
    'SubjectPublicKeyInfo': ser.PublicFormat.SubjectPublicKeyInfo,
    'PKCS1': ser.PublicFormat.PKCS1,
    'OpenSSH': ser.PublicFormat.OpenSSH,
    'CompressedPoint': ser.PublicFormat.CompressedPoint,
    'UncompressedPoint': ser.PublicFormat.UncompressedPoint,
}

parameter_format = {
    'PKCS3': ser.ParameterFormat.PKCS3,
}
