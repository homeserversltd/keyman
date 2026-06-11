#!/usr/bin/env python3
"""Keyman root entry face.

Run naked to see the usage surface.  The implementation lives under
``lib.keyman_installer`` so the old shell/C technology remains intact while new
callers get a safer, explicit installer membrane.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lib.keyman_installer.index import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
