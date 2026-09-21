"""chess-live MCPB entry point: vendored deps first, then the server module."""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_VENDOR = os.path.join(_HERE, "vendor")
if os.path.isdir(_VENDOR) and _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)

# Repoint state + HTTP port at bundle-friendly defaults (overridable via env).
os.environ.setdefault("CHESS_LIVE_STATE", os.path.join(_HERE, "chess-live.json"))
os.environ.setdefault("CHESS_LIVE_PORT", "8765")

sys.path.insert(0, os.path.join(_HERE, "src"))

from chess_live import mcp  # noqa: E402

if __name__ == "__main__":
    mcp.run()
