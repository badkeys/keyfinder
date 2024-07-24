#!/bin/bash
set -euo pipefail

ruff check --select=ALL --ignore=PTH,ANN,D,ERA,S310 keyfinder
black --check --diff keyfinder
