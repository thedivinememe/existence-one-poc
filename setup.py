#!/usr/bin/env python3
"""
Setup script for the Existence One proof of concept.
"""

from setuptools import setup, find_packages

setup(
    name="existence_one_poc",
    version="0.1.0",
    description="Proof of concept showing how binary 0 as !1 breaks cryptography",
    author="Existence One Team",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click>=8.0.0",
        "colorama>=0.4.4",
        "matplotlib>=3.4.0",
        "numpy>=1.20.0",
        "pytest>=7.0.0",
    ],
    entry_points={
        "console_scripts": [
            "existence-demo=cli.quick_demos:cli",
        ],
    },
    python_requires=">=3.8",
)
