#!/bin/sh
# Runs the l2tp_switch test files concurrently, one privileged container per
# shard, and fails if any shard fails.
#
#   tests/run_l2tp_switch_sharded.sh <image> [shards]
#
# <image> is a Linux image with accel-ppp already built AND installed and the
# test requirements present (e.g. `docker commit` of a working build
# container). Every container has its own network namespace, so the shards
# never compete for ports; the repository is mounted read-write at /src.
# Re-create the image after rebuilding: shards run the binary baked into it,
# not the working tree's.
set -eu

image=${1:?usage: $0 <image> [shards]}
shards=${2:-5}
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Balance by file size (a fair proxy for test count and duration): biggest
# file first, each to the currently lightest shard.
python3 - "$repo/tests/accel-pppd/l2tp_switch" "$shards" "$work" <<'PY'
import glob, os, sys
directory, n, work = sys.argv[1], int(sys.argv[2]), sys.argv[3]
files = sorted(glob.glob(os.path.join(directory, "test_*.py")),
               key=os.path.getsize, reverse=True)
load = [0] * n
groups = [[] for _ in range(n)]
for f in files:
    i = load.index(min(load))
    groups[i].append("accel-pppd/l2tp_switch/" + os.path.basename(f))
    load[i] += os.path.getsize(f)
for i, g in enumerate(groups):
    if g:
        open(os.path.join(work, "shard%d" % i), "w").write(" ".join(g))
PY

pids=""
for shard in "$work"/shard*; do
    name=$(basename "$shard")
    docker run --rm --privileged -v "$repo":/src "$image" sh -c \
        "cd /src/tests && python3 -m pytest -q -p no:cacheprovider -m l2tp_switch $(cat "$shard")" \
        >"$work/$name.log" 2>&1 &
    pids="$pids $! $name"
done

status=0
set -- $pids
while [ $# -gt 0 ]; do
    pid=$1 name=$2
    shift 2
    if wait "$pid"; then
        echo "$name: $(tail -n 1 "$work/$name.log")"
    else
        status=1
        echo "$name: FAILED"
        cat "$work/$name.log"
    fi
done
exit $status
