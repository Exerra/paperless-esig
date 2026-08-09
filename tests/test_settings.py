"""Minimal Django settings for the paperless-edoc test suite.

See conftest.py — the parser only touches ``SCRATCH_DIR`` and the
Tika/Gotenberg endpoints, so no full Paperless-ngx settings module is
required to run the unit tests.
"""

import tempfile
from pathlib import Path

SECRET_KEY = "paperless-edoc-tests"
DEBUG = True
USE_TZ = True
TIME_ZONE = "UTC"

SCRATCH_DIR = Path(tempfile.mkdtemp(prefix="paperless-edoc-tests-"))

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
}

TIKA_ENDPOINT = ""
TIKA_GOTENBERG_ENDPOINT = ""
CELERY_TASK_TIME_LIMIT = 60
