#!/bin/bash
set -euo pipefail

# lxml and pygit2 dependencies
export DEBIAN_FRONTEND="noninteractive" 
apt-get update
apt-get -y install libxslt-dev libxml2-dev libgit2-dev
