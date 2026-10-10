"""Test-suite wide configuration.

The application default is the FULL knowledge base (``trc_engine_fullkb``).  The tests
are written against the 24-entry seed KB (database ``trc_engine``), so they are pointed
there explicitly.  Override with ``TRC_TEST_DATABASE_URL`` to use another database.
"""

from __future__ import annotations

import os
import re

_SEED_DB = "trc_engine"


def _seed_url() -> str:
    explicit = os.environ.get("TRC_TEST_DATABASE_URL")
    if explicit:
        return explicit
    from config.settings import Settings

    return re.sub(r"/[^/?]+(\?.*)?$", rf"/{_SEED_DB}\1", Settings().DATABASE_URL)


os.environ["DATABASE_URL"] = _seed_url()
