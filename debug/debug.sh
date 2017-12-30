#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"
GIT_ROOT_DIR="$(git rev-parse --show-toplevel)"

perl -dt -I"${GIT_ROOT_DIR}/src" "${GIT_ROOT_DIR}/src/LDAPGateway.pl"

exit $?
