"""Vercel entrypoint.

Vercel's Python runtime loads the WSGI callable named ``app`` from this file.
The project root is added to the import path because the runtime starts in
``api/`` and the detection package lives one level up.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app  # noqa: E402

app = create_app()
