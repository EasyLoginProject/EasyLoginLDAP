#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"
GIT_ROOT_DIR="$(git rev-parse --show-toplevel)"

perl -d -I"${GIT_ROOT_DIR}/src" "${GIT_ROOT_DIR}/src/simple-server.pl"

exit $?
