#!/usr/bin/env bash
#
# Run CNI plugin tests.
#
set -e
set -x

source ./build_windows.sh

echo "Running tests"

PLUGINS=$(cat plugins/windows_only.txt | tr '\n' ' ')
GINKGO_FLAGS="-p -r --randomizeAllSpecs --randomizeSuites --failOnPending --progress pkg/hns $PLUGINS"

bash -c "set -x; cd ${GOPATH}/src/${REPO_PATH}; PATH='${GOROOT}/bin:$(pwd)/bin:${PATH}' ginkgo ${GINKGO_FLAGS}"
