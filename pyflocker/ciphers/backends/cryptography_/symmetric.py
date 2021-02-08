"""Cryptography backend specific templates and tools for symmetric ciphers."""

import typing

from cryptography import exceptions as bkx

from ... import base, exc


class NonAEADCipherTemplate(base.BaseNonAEADCipher):
    """
    Template class to provide the default behavior if BaseNonAEADCipher.

    Subclasses need to provide:
        - `_encrypting`
        - `_ctx`
    """

    _encrypting: bool
    _ctx: typing.Any

    def is_encrypting(self):
        return self._encrypting

    def update(self, data):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        return self._ctx.update(data)

    def update_into(self, data, out):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._ctx.update_into(data, out)

    def finalize(self):
        if not self._ctx:
            raise exc.AlreadyFinalized

        self._ctx = None


class AEADCipherTemplate(base.BaseAEADCipher):
    """
    Template class to provide the default behavior if BaseAEADCipher.

    Subclasses need to provide the following attributes:
        - `_encrypting`
        - `_ctx`
    """

    # these are *not* class variables
    _updated: bool = False
    _tag: typing.Optional[bytes] = None

    _encrypting: bool
    _ctx: typing.Any

    def is_encrypting(self):
        return self._encrypting

    def update(self, data):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._updated = True
        return self._ctx.update(data)

    def update_into(self, data, out):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._updated = True
        self._ctx.update_into(data, out)

    def authenticate(self, data):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        if self._updated:
            raise TypeError
        self._ctx.authenticate_additional_data(data)

    def finalize(self, tag=None):
        if self._ctx is None:
            raise exc.AlreadyFinalized

        if not self.is_encrypting():
            if tag is None:
                raise ValueError("tag is required for finalization")

            ctx, self._ctx = self._ctx, None
            try:
                ctx.finalize_with_tag(tag)
            except bkx.InvalidTag as e:
                raise exc.DecryptionError from e
        else:
            ctx, self._ctx = self._ctx, None
            ctx.finalize()
            self._tag = ctx.tag

    def calculate_tag(self):
        if self._ctx is not None:
            raise exc.NotFinalized

        return self._tag
