#!/bin/bash
set -euo pipefail

ruff check --select=ALL --ignore=PTH,ANN,D,ERA keyfinder
black --check --diff keyfinder
