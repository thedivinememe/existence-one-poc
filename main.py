#!/usr/bin/env python3
"""
Main entry point for the Existence One proof of concept.

This script provides a convenient entry point to run the CLI commands
without dealing with Python package import issues.
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
