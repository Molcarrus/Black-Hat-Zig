#!/usr/bin/env bash
set -e

# Build all Zig projects in the repository

ROOT_DIR="$(dirname "$(realpath "$0")")/"
cd "$ROOT_DIR"

failed=0

for build_file in $(git ls-files -- '*build.zig'); do
    dir=$(dirname "$build_file")
    echo "Building $dir"
    (cd "$dir" && zig build) || failed=1
    echo
done

exit $failed
