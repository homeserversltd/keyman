#!/usr/bin/env python3
"""Keyman root entry face.

The source-declared ``mgla`` verb family is dispatched here alongside the
existing Python installer. The Rust keyman binary enters this same front door
for MGLA operations; credential storage and export stay on the shell/C ladder.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lib.keyman_installer.index import main as installer_main  # noqa: E402


def main() -> int:
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "mgla":
        from lib.keyman_mgla.index import main as mgla_main

        return mgla_main(arguments[1:])
    return installer_main()


if __name__ == "__main__":
    raise SystemExit(main())
