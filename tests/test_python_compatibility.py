"""Packaging guardrails for the supported Python range, including 3.14.1."""
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import cygnus


def test_runtime_meets_minimum_supported_python():
    assert sys.version_info >= (3, 11)


def test_package_metadata_explicitly_supports_python_314():
    metadata=tomllib.loads((Path(__file__).parents[1]/"pyproject.toml").read_text())
    project=metadata["project"]
    assert project["requires-python"] == ">=3.11"
    assert "Programming Language :: Python :: 3.14" in project["classifiers"]


def test_package_version_is_consistent():
    metadata=tomllib.loads((Path(__file__).parents[1]/"pyproject.toml").read_text())
    assert cygnus.__version__ == metadata["project"]["version"]
