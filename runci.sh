#!/bin/bash
set -euo pipefail

ruff check --select=ALL --ignore=PTH,ANN,D,ERA,S310,T201,C,PLR,S501,FIX,TD,FBT,I001 keyfinder.py gitkeyfinder
python -m unittest -v
