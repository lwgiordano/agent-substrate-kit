#!/usr/bin/env python3
"""Compatibility shim (v3.9.1): the scanner moved to check_leaks.py."""
import runpy, sys
from pathlib import Path
sys.argv[0] = str(Path(__file__).with_name('check_leaks.py'))
runpy.run_path(sys.argv[0], run_name='__main__')
