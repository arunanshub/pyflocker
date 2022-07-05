from __future__ import annotations

import typing
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import padding as padding_
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, ECDSA

from .. import asymmetric
from . import Hash

if TYPE_CHECKING:  # pragma: no cover
    from ... import base


def get_OAEP(padding: base.BaseAsymmetricPadding) -> padding_.OAEP:
    """Construct a pyca/cryptography specific OAEP object.

    Args:
        padding (OAEP): An OAEP object.

    Returns:
        OAEP object:
            An OAEP encryptor/decryptor object depending on the key, from the
            cryptography backend.
    """
    if not isinstance(padding, asymmetric.OAEP):  # pragma: no cover
        raise TypeError("padding must be an instance of OAEP.")
    if not isinstance(padding.mgf, asymmetric.MGF1):
        raise TypeError("MGF must be an instance of MGF1.")
    return padding_.OAEP(
        mgf=padding_.MGF1(
            Hash._get_hash_algorithm(padding.mgf.hashfunc),
        ),
        algorithm=Hash._get_hash_algorithm(padding.hashfunc),
        label=padding.label,
    )


def get_PSS(padding: base.BaseAsymmetricPadding) -> padding_.PSS:
    """Construct a pyca/cryptography specific PSS object.

    Args:
        padding (PSS): A PSS object.

    Returns:
        PSS object: An PSS signer/verifier object, depending on the key.
    """
    if not isinstance(padding, asymmetric.PSS):  # pragma: no cover
        raise TypeError("padding must be an instance of PSS.")
    if not isinstance(padding.mgf, asymmetric.MGF1):
        raise TypeError("MGF must be an instance of MGF1.")
    return padding_.PSS(
        mgf=padding_.MGF1(Hash._get_hash_algorithm(padding.mgf.hashfunc)),
        salt_length=padding_.PSS.MAX_LENGTH
        if padding.salt_length is None
        else padding.salt_length,
    )


def get_ECDH(algorithm: base.BaseEllepticCurveExchangeAlgorithm) -> ECDH:
    """Return an ECDH object for key exchange.

    Args:
        algorithm: The algorithm to use.

    Returns: ECDH key exchange object.
    """
    if not isinstance(algorithm, asymmetric.ECDH):  # pragma: no cover
        raise TypeError("algorithm must be an instance of ECDH")
    return ECDH()


def get_ECDSA(
    algorithm: base.BaseEllepticCurveSignatureAlgorithm,
) -> type[ECDSA]:
    """Return an ECDSA callable for signing/verification.

    The object is not constructed until the key is signing/verifying.

    Args:
        algorithm: The algorithm to use.

    Returns: Signer/Verifier callable.
    """
    if not isinstance(algorithm, asymmetric.ECDSA):  # pragma: no cover
        raise TypeError("algorithm must be an instance of ECDSA")
    return ECDSA


PADDINGS: dict[type[base.BaseAsymmetricPadding], typing.Callable] = {
    asymmetric.OAEP: get_OAEP,
    asymmetric.PSS: get_PSS,
}


EC_EXCHANGE_ALGORITHMS: dict[
    type[base.BaseEllepticCurveExchangeAlgorithm],
    typing.Callable,
] = {
    asymmetric.ECDH: get_ECDH,
}

EC_SIGNATURE_ALGORITHMS: dict[
    type[base.BaseEllepticCurveSignatureAlgorithm],
    typing.Callable,
] = {
    asymmetric.ECDSA: get_ECDSA,
    # asymmetric.EdDSA: get_EdDSA,
}


def get_padding_algorithm(
    padding: base.BaseAsymmetricPadding,
    *args: typing.Any,
    **kwargs: typing.Any,
) -> padding_.AsymmetricPadding:
    try:
        return PADDINGS[type(padding)](*args, **kwargs)
    except KeyError as e:
        raise TypeError(
            f"Invalid padding algorithm type: {type(padding)}"
        ) from e


def get_ec_exchange_algorithm(
    algorithm: base.BaseEllepticCurveExchangeAlgorithm,
    *args: typing.Any,
    **kwargs: typing.Any,
) -> typing.Any:
    try:
        return EC_EXCHANGE_ALGORITHMS[type(algorithm)](*args, **kwargs)
    except KeyError as e:
        raise TypeError(
            f"Invalid exchange algorithm type: {type(algorithm)}"
        ) from e


def get_ec_signature_algorithm(
    algorithm: base.BaseEllepticCurveSignatureAlgorithm,
    *args: typing.Any,
    **kwargs: typing.Any,
) -> typing.Any:
    try:
        return EC_SIGNATURE_ALGORITHMS[type(algorithm)](*args, **kwargs)
    except KeyError as e:
        raise TypeError(
            f"Invalid signature algorithm type: {type(algorithm)}"
        ) from e
