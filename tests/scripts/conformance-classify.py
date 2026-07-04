#!/usr/bin/env python3
"""Classify one conformance plan's per-module results into 3 buckets.

Reads the raw per-module result lines a plan run produced and an
expected-failures allowlist, then sorts every module into one of:

  GREEN          FINISHED with PASSED | WARNING | SKIPPED.
                 (WARNING and SKIPPED count as green on purpose:
                 kubauth's minimal user model warns on some profile
                 claims, and oidcc-refresh-token skips. Neither is a
                 spec violation.)
  EXPECTED-FAIL  not green, AND listed in the allowlist with a state
                 (and, if the entry pins one, a result) that matches.
  UNEXPECTED     everything else, i.e. either
                   - green BUT listed   -> the baseline is stale, the
                     module now passes and must be removed from the
                     allowlist (a fix landed); or
                   - not green AND not listed (or listed with a
                     mismatching state/result) -> a regression.

The gate is symmetric: it fails on BOTH drift directions. A future
OIDC fix that flips a listed module green fails the build (drop it
from the list) exactly as a fresh regression does. The allowlist is
therefore a hand-curated baseline, never auto-generated from a run
(that would launder regressions into the baseline).

Input formats
-------------
results file: one module per line, whitespace-separated, as emitted by
conformance-run.sh:

    <module>  <state>  <result>

Lines that are blank or start with '#' are ignored. <result> may be
absent, '?' or '-' (the suite did not record a clean result, common
for INTERRUPTED modules) -- all three normalise to NONE.

allowlist file: a small, fixed-schema YAML subset (NO PyYAML
dependency -- the suite host only has the stdlib). Shape:

    plan: <plan-name>
    suite: <suite-version>
    expected_failures:
      - module: <module-name>
        state: FINISHED | INTERRUPTED | ...   # OPTIONAL; omit when racy
        result: FAILED            # OPTIONAL; omit when noisy (?/-)
        reason: "..."             # free text, ignored by the gate
        ref: "COVERAGE.md#bNN"    # ignored by the gate
      - module: ...

Only `module` is required; `state`, `result`, `reason` and `ref` are
optional. Omitting `state` matches ANY non-green terminal state -- use
it for modules the suite leaves in a racy INTERRUPTED/FINISHED state
(e.g. browser-driven logout gaps), where the exact terminal state
carries no signal but the module is still a known failure. A listed
module that turns GREEN is always reported (via the is-green path), so
omitting state never hides a landed fix. An empty / absent
`expected_failures:` means
"no module may fail" (used for oidcc-config). The parser is strict:
an unknown key or a malformed entry raises, so a format drift fails
loudly instead of silently letting a regression through.

Usage:
    conformance-classify.py <plan-name> <results-file> <allowlist-file>

Exit codes:
    0  the UNEXPECTED bucket is empty for this plan
    1  one or more UNEXPECTED modules (regression or stale baseline)
    2  usage / parse error
"""

import sys

GREEN_RESULTS = {"PASSED", "WARNING", "SKIPPED"}
# Tokens the suite uses when it did not record a real result.
_NONE_TOKENS = {"", "?", "-", "NONE"}


def _norm_result(value):
    """Normalise a result token; the no-result sentinels all map to NONE."""
    v = (value or "").strip().upper()
    return "NONE" if v in _NONE_TOKENS else v


def die(msg):
    sys.stderr.write("conformance-classify: %s\n" % msg)
    sys.exit(2)


def parse_results(path):
    """Parse a results file into an ordered list of (module, state, result)."""
    out = []
    try:
        with open(path, "r") as fh:
            raw = fh.read()
    except OSError as exc:
        die("cannot read results file %r: %s" % (path, exc))
    for lineno, line in enumerate(raw.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) < 2:
            die("results %s:%d: need at least '<module> <state>', got %r"
                % (path, lineno, line))
        module = parts[0]
        state = parts[1].upper()
        result = _norm_result(parts[2] if len(parts) >= 3 else "")
        out.append((module, state, result))
    return out


# ---------------------------------------------------------------------------
# Minimal allowlist reader. Deliberately NOT a general YAML parser: it
# accepts exactly the schema documented above and rejects anything else,
# so a malformed allowlist is a hard error rather than a silent
# misclassification.
# ---------------------------------------------------------------------------

_TOP_SCALARS = ("plan", "suite")
_ENTRY_KEYS = ("module", "state", "result", "reason", "ref", "issue")
_ENTRY_REQUIRED = ("module",)


def _strip_inline_comment(value):
    """Drop a trailing ' # ...' comment from an unquoted scalar."""
    # Only strip when the '#' is preceded by whitespace, so a '#'
    # inside a value (e.g. COVERAGE.md#b15) survives.
    out = []
    prev_space = False
    for ch in value:
        if ch == "#" and (prev_space or not out):
            break
        out.append(ch)
        prev_space = ch in (" ", "\t")
    return "".join(out).strip()


def _unquote(value):
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    return _strip_inline_comment(v)


def parse_allowlist(path):
    """Parse the constrained allowlist YAML. Returns (meta, entries).

    meta is a dict with optional 'plan'/'suite'. entries is a list of
    dicts each carrying at least 'module' and 'state' (upper-cased),
    plus a normalised 'result' (NONE when the entry pins no result).
    """
    try:
        with open(path, "r") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        die("cannot read allowlist %r: %s" % (path, exc))

    meta = {}
    entries = []
    in_list = False
    cur = None

    def flush():
        if cur is None:
            return
        for req in _ENTRY_REQUIRED:
            if req not in cur:
                die("allowlist %s: entry missing required key %r: %r"
                    % (path, req, cur))
        if "state" in cur:
            cur["state"] = cur["state"].upper()
        cur["result"] = _norm_result(cur.get("result", ""))
        entries.append(cur)

    for lineno, raw in enumerate(lines, 1):
        # Drop full-line comments and blanks.
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(raw) - len(raw.lstrip(" "))

        # Top-level key (no indent).
        if indent == 0:
            flush()
            cur = None
            in_list = False
            if ":" not in raw:
                die("allowlist %s:%d: expected 'key:' at top level, got %r"
                    % (path, lineno, raw))
            key, _, val = raw.partition(":")
            key = key.strip()
            val = _unquote(val)
            if key in _TOP_SCALARS:
                meta[key] = val
            elif key == "expected_failures":
                if val not in ("", "[]"):
                    die("allowlist %s:%d: 'expected_failures' takes a block "
                        "list, not an inline value %r" % (path, lineno, val))
                in_list = True
            else:
                die("allowlist %s:%d: unknown top-level key %r"
                    % (path, lineno, key))
            continue

        # Indented content must belong to expected_failures.
        if not in_list:
            die("allowlist %s:%d: indented line outside 'expected_failures': %r"
                % (path, lineno, raw))

        # New list item: '- key: value'.
        if stripped.startswith("- "):
            flush()
            cur = {}
            item = stripped[2:]
            if ":" not in item:
                die("allowlist %s:%d: list item must start a 'key: value' "
                    "mapping, got %r" % (path, lineno, raw))
            key, _, val = item.partition(":")
            key = key.strip()
            if key not in _ENTRY_KEYS:
                die("allowlist %s:%d: unknown entry key %r" % (path, lineno, key))
            cur[key] = _unquote(val)
            continue

        # Continuation key of the current item: 'key: value'.
        if cur is None:
            die("allowlist %s:%d: mapping key before any '- ' list item: %r"
                % (path, lineno, raw))
        if ":" not in stripped:
            die("allowlist %s:%d: expected 'key: value', got %r"
                % (path, lineno, raw))
        key, _, val = stripped.partition(":")
        key = key.strip()
        if key not in _ENTRY_KEYS:
            die("allowlist %s:%d: unknown entry key %r" % (path, lineno, key))
        cur[key] = _unquote(val)

    flush()
    return meta, entries


def classify(modules, entries):
    """Sort modules into the 3 buckets.

    Returns (green, expected_fail, unexpected, unused_entries) where the
    first three are lists of (module, state, result, note) and
    unused_entries is the list of allowlist entries that matched no
    not-green module (a listed module that turned out green is reported
    as UNEXPECTED via the per-module path, so unused_entries here means
    the module did not appear in the run at all -- also a stale entry).
    """
    # Index allowlist by module (a module appears at most once).
    by_module = {}
    for e in entries:
        if e["module"] in by_module:
            die("allowlist lists module %r twice" % e["module"])
        by_module[e["module"]] = e

    green, expected_fail, unexpected = [], [], []
    matched_modules = set()

    for module, state, result in modules:
        is_green = state == "FINISHED" and result in GREEN_RESULTS
        entry = by_module.get(module)

        if is_green:
            if entry is not None:
                # Listed but now passing -> stale baseline.
                matched_modules.add(module)
                unexpected.append((module, state, result, "unexpectedly-passed"))
            else:
                green.append((module, state, result, ""))
            continue

        # Not green.
        if entry is None:
            unexpected.append((module, state, result, "regression (not in allowlist)"))
            continue

        # Listed and not green: does state/result match the entry?
        # `state` is optional: an entry that omits it matches any non-green
        # terminal state (for modules the suite leaves in a racy
        # INTERRUPTED/FINISHED state, e.g. browser-driven logout gaps).
        matched_modules.add(module)
        entry_state = entry.get("state")
        state_ok = entry_state is None or state == entry_state
        result_ok = entry["result"] == "NONE" or entry["result"] == result
        if state_ok and result_ok:
            expected_fail.append((module, state, result, entry.get("ref", "")))
        else:
            want = entry_state if entry_state is not None else "ANY"
            if entry["result"] != "NONE":
                want += "/" + entry["result"]
            got = state if result == "NONE" else state + "/" + result
            unexpected.append(
                (module, state, result,
                 "listed as %s but observed %s" % (want, got)))

    # Entries that never matched any module in the run (the module
    # vanished from the plan, or was misspelled) -> stale baseline.
    unused = [e for e in entries if e["module"] not in matched_modules]
    return green, expected_fail, unexpected, unused


def main(argv):
    if len(argv) != 4:
        sys.stderr.write(
            "usage: conformance-classify.py <plan-name> <results-file> "
            "<allowlist-file>\n")
        return 2

    plan = argv[1]
    results = parse_results(argv[2])
    _meta, entries = parse_allowlist(argv[3])

    green, xfail, unexpected, unused = classify(results, entries)

    # One TL;DR line per plan (always printed, to stdout).
    label = (plan + ":").ljust(44)
    verdict = "OK" if not unexpected and not unused else "FAIL"
    print("%s %3d green / %3d xfail / %3d unexpected  -> %s"
          % (label, len(green), len(xfail), len(unexpected) + len(unused),
             verdict))

    # Spell out only the unexpected modules, in full.
    for module, state, result, note in unexpected:
        shown = state if result == "NONE" else "%s %s" % (state, result)
        print("    UNEXPECTED  %-70s %-18s %s" % (module, shown, note))
    for e in unused:
        want = e.get("state", "ANY")
        if e["result"] != "NONE":
            want += "/" + e["result"]
        print("    UNEXPECTED  %-70s %-18s stale entry: module not in run "
              "(listed %s)" % (e["module"], "ABSENT", want))

    return 0 if (not unexpected and not unused) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
