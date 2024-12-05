#!/bin/bash
set -euo pipefail

# sometimes necessary for lxml installation via pip in CI
export DEBIAN_FRONTEND="noninteractive" 
apt-get update
apt-get -y install libxslt-dev libxml2-dev
