"""Utility tools common to both backend interfaces."""


def updater(locking, cipherup, hashup, *,
            shared=True, buffered=True):
    """todo
    """
    if hashup is None:
        return cipherup

    if not buffered:
        return _bytes_updater(
            locking, cipherup, hashup)

    if locking:
        if not shared:
            def fn(rbuf, wbuf):
                cipherup(rbuf, wbuf)
                ix = len(wbuf) - len(rbuf)
                hashup(wbuf[:-ix])
            return fn

        def fn(rbuf, wbuf):
            cipherup(rbuf, wbuf)
            # assume that rbuf is filled with data
            # written to wbuf.
            hashup(rbuf)
    else:
        def fn(rbuf, wbuf):
            hashup(rbuf)
            cipherup(rbuf, wbuf)
    return fn


def _bytes_updater(locking, cipherup, hashup):
    if locking:
        def fn(data):
            data = cipherup(data)
            hashup(data)
            return data
    else:
        def fn(data):
            hashup(data)
            return cipherup(data)
    return fn

