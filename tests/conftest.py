import os
import sys

# Make `main` and the `vulnlens` package importable when running `pytest` from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
