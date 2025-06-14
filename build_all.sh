#!/usr/bin/env bash
set -e

ROOT_DIR="$(dirname "$(realpath "$0")")/src"
cd "$ROOT_DIR"

failed=0

for build_file in $(find . -type f -name build.zig); do
    dir=$(dirname "$build_file")
    echo "Building $dir"
    (cd "$dir" && zig build) || failed=1
    echo
done

exit $failed
