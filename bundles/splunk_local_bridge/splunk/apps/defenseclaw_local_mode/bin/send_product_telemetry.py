#!/usr/bin/env python3

import sys
from pathlib import Path


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from product_telemetry_sender import main


if __name__ == "__main__":
    raise SystemExit(main())
