#!/usr/bin/env bash
set -e

TEST_USERNS=${TEST_USERNS:-}
TEST_KEEP_ON_FAILURE=${TEST_KEEP_ON_FAILURE:-}

cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

if [[ -n "$TEST_USERNS" ]]; then
    echo "Enabled user namespace testing"
    export \
        CONTAINER_UID_MAPPINGS="0:100000:100000" \
        CONTAINER_GID_MAPPINGS="0:200000:100000"

    # Needed for RHEL
    if [[ -w /proc/sys/user/max_user_namespaces ]]; then
        echo 15000 >/proc/sys/user/max_user_namespaces
    fi
fi

# Load the helpers.
. helpers.bash

# Tests to run. Default is "." (i.e. the current directory).
TESTS=("${@:-.}")

ret=0
for test in ${TESTS}; do
    if [[ -d ${test} && -f ${test}/.should_be_serial ]]; then
        JOBS=1
    else
        JOBS=$(($(nproc --all) * 4))
        echo "JOBS: ${JOBS}"
    fi
    bats --jobs "$JOBS" --tap "${test}"
    ret=$(($ret || $?))
done

return $ret
