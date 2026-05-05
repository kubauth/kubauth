#!/usr/bin/env bash
#
# Run chainsaw against a path with concise output: only PASS / FAIL /
# SKIP lines + the Tests Summary block. Full chainsaw output is
# tee-ed to .tmp/e2e.log so the developer can dig in if anything
# fails.
#
# Why a wrapper script:
# Chainsaw has no `--quiet` flag. Its default output prefixes every
# step with `sink.go:56: | <ts> | <test> | <step> | ...` — useful in
# CI where the log is the artefact, but a wall of text in a local
# terminal. The reviewer's "bruit visuel" point.
#
# Usage:
#   run-e2e-quiet.sh <chainsaw-target>
#   run-e2e-quiet.sh tests/e2e
#   run-e2e-quiet.sh tests/e2e/01-smoke-login

set -euo pipefail

# shellcheck source=lib/env.sh
source "$(dirname "$0")/lib/env.sh"

require_bin chainsaw

if (($# == 0)); then
  die "usage: $0 <chainsaw-target>"
fi

# We run from tests/ (the Makefile's working dir); .tmp is gitignored.
mkdir -p .tmp
LOG=.tmp/e2e.log

# `set -o pipefail` makes chainsaw's exit code propagate through the
# pipe even though tee+grep would otherwise mask it.
set -o pipefail

if chainsaw test --config chainsaw.yaml "$@" 2>&1 | tee "$LOG" \
   | grep --line-buffered -E '^[[:space:]]*--- (PASS|FAIL|SKIP):|^FAIL$|^PASS$|^Tests Summary|^- (Passed|Failed|Skipped) tests'; then
  ok "e2e suite green — full log: $LOG"
else
  rc=$?
  err "e2e failed (rc=$rc) — full log: $LOG"
  exit "$rc"
fi
