#!/usr/bin/env python3
"""
Main module for the Existence One proof of concept.

This allows running the package directly with:
python -m existence_one_poc
"""

import sys
import os

# Add the project root to the Python path to enable imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import the CLI module
from cli.quick_demos import cli

if __name__ == "__main__":
    # Run the CLI
    cli()
