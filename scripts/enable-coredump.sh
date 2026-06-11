#!/usr/bin/env bash
#
# Enable core dumps for debugging crashing processes (e.g. the `server` binary).
#
# Core dumps require TWO things:
#   1. A per-shell core size limit (`ulimit -c`) that is > 0.
#   2. A kernel `core_pattern` that writes a file instead of piping to a
#      crash handler such as apport (the default on Ubuntu drops cores from
#      locally-built binaries).
#
# A RELATIVE core_pattern (no leading '/') makes the kernel write the core into
# the crashing process's current working directory - i.e. the directory you
# launched the binary from.
#
# Because `ulimit` only affects the current shell and its children, SOURCE this
# script so the limit applies to your interactive shell:
#
#     source scripts/enable-coredump.sh
#
# Running it normally (`./scripts/enable-coredump.sh`) still sets the system
# core_pattern, but the ulimit will only apply to the script's own subshell.

set -u

# Relative pattern -> core is written to the process's working directory.
CORE_PATTERN="${CORE_PATTERN:-core.%e.%p}"

# 1. Raise the per-shell core dump size limit.
ulimit -c unlimited

# 2. Point core_pattern at a writable file (requires root).
if [ "$(cat /proc/sys/kernel/core_pattern)" != "${CORE_PATTERN}" ]; then
    echo "Setting kernel core_pattern -> ${CORE_PATTERN} (needs sudo)"
    echo "${CORE_PATTERN}" | sudo tee /proc/sys/kernel/core_pattern >/dev/null
fi

echo "Core dumps enabled:"
echo "  ulimit -c     = $(ulimit -c)"
echo "  core_pattern  = $(cat /proc/sys/kernel/core_pattern)"
echo
echo "Cores will be written to the binary's working directory: ./core.<exe>.<pid>"
echo "Inspect with: gdb <binary> ./core.<exe>.<pid> -batch -ex 'thread apply all bt'"

# Reminder if not sourced: the ulimit above won't reach the parent shell.
(return 0 2>/dev/null) || {
    echo
    echo "NOTE: run with 'source ${0}' so 'ulimit -c unlimited' affects your shell."
}
