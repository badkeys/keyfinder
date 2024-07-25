#!/bin/bash
set -euo pipefail

ruff check --select=ALL --ignore=PTH,ANN,D,ERA,S310,T201,C,PLR keyfinder
black --check --diff keyfinder
