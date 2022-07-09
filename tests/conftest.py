from __future__ import annotations

import os

from hypothesis import settings

settings.register_profile("dev", deadline=None)
settings.register_profile(
    "ci",
    max_examples=200,
    parent=settings.get_profile("dev"),
)

settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "dev"))
