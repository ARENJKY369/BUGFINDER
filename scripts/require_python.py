"""Fail unless the running interpreter has the requested exact version."""
from __future__ import annotations
import argparse,sys

parser=argparse.ArgumentParser()
parser.add_argument("version",help="required exact version, for example 3.14.1")
args=parser.parse_args()
actual=".".join(map(str,sys.version_info[:3]))
if actual!=args.version:
    raise SystemExit(f"Python {args.version} required for this compatibility run; found {actual}")
print(f"Exact Python compatibility runtime confirmed: {actual}")
