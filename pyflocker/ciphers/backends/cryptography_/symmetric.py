from ... import base, exc


class NonAEADCipherTemplate(base.BaseNonAEADCipher):
    """
    Template class to provide the default behavior if BaseNonAEADCipher.

    Subclasses need to provide:
        - `_encrypting`
        - `_ctx`
    """

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
        - `_updated`
        - `_tag`
    """

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

        if not self._encrypting and tag is None:
            raise ValueError("tag is required for finalization")

        ctx, self._ctx = self._ctx, None

        try:
            if not self._encrypting:
                ctx.finalize_with_tag(tag)
            else:
                ctx.finalize()
                self._tag = ctx.tag
        except ValueError as e:
            raise exc.DecryptionError from e

    def calculate_tag(self):
        if self._ctx is not None:
            raise exc.NotFinalized

        return self._tag
