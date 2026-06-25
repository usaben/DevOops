"""Shared pytest fixtures."""

import os
import sys
from pathlib import Path

# Ensure the app package is importable when pytest is run from any cwd.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))