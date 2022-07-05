from __future__ import annotations

import os

from hypothesis import settings

settings.register_profile("dev", deadline=1000)
settings.register_profile(
    "ci",
    max_examples=500,
    parent=settings.get_profile("dev"),
)

settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "dev"))
