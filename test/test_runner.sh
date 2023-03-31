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
TESTS_ROOT=("${@:-.}")
SERIAL_TESTS=("${TESTS_ROOT}/serial")

# The number of parallel jobs to execute
export JOBS=${JOBS:-$(($(nproc --all) * 4))}

# Run the tests.
bats --jobs "$JOBS" --tap "${TESTS_ROOT[@]}"
parallel_test_result=$?
bats --tap "${SERIAL_TESTS[@]}"
serial_test_result=$?

echo "parallel: ${parallel_test_result}"
echo "serial: ${serial_test_result}"

[ parallel_test_result && serial_test_result ]
