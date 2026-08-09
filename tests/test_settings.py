"""Minimal Django settings for the paperless-esig test suite.

See conftest.py — the parser only touches ``SCRATCH_DIR`` and the
Tika/Gotenberg endpoints, so no full Paperless-ngx settings module is
required to run the unit tests.
"""

import tempfile
from pathlib import Path

SECRET_KEY = "paperless-esig-tests"
DEBUG = True
USE_TZ = True
TIME_ZONE = "UTC"

SCRATCH_DIR = Path(tempfile.mkdtemp(prefix="paperless-esig-tests-"))

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
}

TIKA_ENDPOINT = ""
TIKA_GOTENBERG_ENDPOINT = ""
CELERY_TASK_TIME_LIMIT = 60
