#!/usr/bin/env bash
# =============================================================================
# verify-pipeline.sh — SWAL local CI / reality pipeline (generic)
# Protocol: GitCore 3.8.0 (REQ-007 local CI preference)
#
# Verifies, feature by feature, that .gitcore/features.json claims match:
#   1. Real code paths on disk          (implemented_in exists)
#   2. SRS REQ-IDs exist in REQUIREMENTS.md (docs/SRS/REQUIREMENTS.md)
#   3. User stories exist in USER-STORIES.md (docs/SRS/USER-STORIES.md)
#   4. Tests referenced are present in source (best-effort symbol grep)
#   5. Code compiles / builds            [--check]
#   6. Tests run green                   [--test]
#
# Stack auto-detection (v1): rust (cargo) | pnpm | npm.
# Override with VERIFY_STACK=rust|pnpm|npm.
#
# Usage:
#   bash .gitcore/scripts/verify-pipeline.sh            # fast: paths + SRS + stories
#   bash .gitcore/scripts/verify-pipeline.sh --check    # + build/compile
#   bash .gitcore/scripts/verify-pipeline.sh --test     # + test suite
#   bash .gitcore/scripts/verify-pipeline.sh --json     # machine-readable report
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FEATURES_JSON="$ROOT/.gitcore/features.json"
SRS_MD="$ROOT/docs/SRS/REQUIREMENTS.md"
STORIES_MD="$ROOT/docs/SRS/USER-STORIES.md"
PYTHON="${PYTHON:-python3}"

DO_CHECK=0; DO_TEST=0; DO_JSON=0
for arg in "$@"; do
  case "$arg" in
    --check) DO_CHECK=1 ;;
    --test)  DO_TEST=1 ;;
    --json)  DO_JSON=1 ;;
    *) echo "Unknown arg: $arg" >&2; exit 2 ;;
  esac
done

# --- stack detection --------------------------------------------------------
detect_stack() {
  [ -n "${VERIFY_STACK:-}" ] && { echo "$VERIFY_STACK"; return; }
  [ -f "$ROOT/Anchor.toml" ] && [ -f "$ROOT/programs/Cargo.toml" ] && { echo "anchor"; return; }
  [ -f "$ROOT/Cargo.toml" ] && { echo "rust"; return; }
  [ -f "$ROOT/pnpm-workspace.yaml" ] || [ -f "$ROOT/pnpm-lock.yaml" ] && { echo "pnpm"; return; }
  [ -f "$ROOT/package.json" ] && { echo "npm"; return; }
  echo "unknown"
}
STACK="$(detect_stack)"

if [ ! -f "$FEATURES_JSON" ]; then
  echo "WARN: $FEATURES_JSON not found — running build/test checks only." >&2
  FEATURES_PRESENT=0
else
  FEATURES_PRESENT=1
fi

# ---------------------------------------------------------------------------
# Helper: lenient JSON parse (escapes literal control chars inside strings)
# ---------------------------------------------------------------------------
LENIENT_PY="$ROOT/.gitcore/scripts/lib/load_lenient.py"
mkdir -p "$(dirname "$LENIENT_PY")"
if [ ! -f "$LENIENT_PY" ]; then
cat > "$LENIENT_PY" <<'PYEOF'
import json, sys
def load_lenient(path):
    raw = open(path, encoding="utf-8", errors="replace").read()
    out, in_str, escaped = [], False, False
    for c in raw:
        if in_str:
            if escaped: out.append(c); escaped = False
            elif c == "\\": out.append(c); escaped = True
            elif c == '"': in_str = False; out.append(c)
            elif ord(c) < 0x20: out.append("\\u%04x" % ord(c))
            else: out.append(c)
        else:
            if c == '"': in_str = True
            out.append(c)
    return json.loads("".join(out))
if __name__ == "__main__":
    d = load_lenient(sys.argv[1])
    print(json.dumps(d, indent=2, ensure_ascii=False))
PYEOF
fi

# ---------------------------------------------------------------------------
# Extraction: emit one line per feature: id|pct|req_ids|user_stories|implemented_in|tests
# ---------------------------------------------------------------------------
EXTRACT_PY="$ROOT/.gitcore/scripts/lib/extract_features.py"
cat > "$EXTRACT_PY" <<PYEOF
import json, sys, os
sys.path.insert(0, "$ROOT/.gitcore/scripts/lib")
from load_lenient import load_lenient
d = load_lenient(sys.argv[1])
feats = d.get("features", [])
if isinstance(feats, dict):
    feats = list(feats.values())
for f in feats:
    if not isinstance(f, dict):
        continue
    def to_csv(v):
        if isinstance(v, list):
            return ",".join(str(x) for x in v)
        return str(v or "")
    reqs = to_csv(f.get("req_ids"))
    us = to_csv(f.get("user_stories"))
    impl = f.get("implemented_in", "") or ""
    tests = to_csv(f.get("tests"))
    print(f'{f["id"]}|{f.get("progress_pct",0)}|{reqs}|{us}|{impl}|{tests}')
PYEOF

declare -a FAILED=()
TOTAL=0; PASS=0; FAIL=0

if [ "$FEATURES_PRESENT" -eq 1 ]; then
  while IFS='|' read -r fid pct reqs us impl tests; do
    TOTAL=$((TOTAL+1))
    problems=""

    # 1. implemented_in paths exist (file OR directory, brace expansion)
    IFS=',' read -ra IMPL <<< "$impl"
    for p in "${IMPL[@]}"; do
      p_trim="$(echo "$p" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -z "$p_trim" ] && continue
      if echo "$p_trim" | grep -q '{'; then
        for expanded in $(eval echo "$p_trim" 2>/dev/null); do
          if [ ! -e "$ROOT/$expanded" ]; then problems="${problems}MISSING_PATH:$expanded "; fi
        done
      elif [ ! -e "$ROOT/$p_trim" ]; then
        problems="${problems}MISSING_PATH:$p_trim "
      fi
    done

    # 2. req_ids exist in SRS (only if SRS exists)
    if [ -f "$SRS_MD" ]; then
      IFS=',' read -ra REQS <<< "$reqs"
      for r in "${REQS[@]}"; do
        [ -z "$r" ] && continue
        if ! grep -q "^## $r:" "$SRS_MD"; then problems="${problems}NO_REQ:$r "; fi
      done
    fi

    # 3. user_stories exist in stories file (only if stories file exists)
    if [ -f "$STORIES_MD" ]; then
      IFS=',' read -ra USES <<< "$us"
      for u in "${USES[@]}"; do
        [ -z "$u" ] && continue
        if ! grep -q "^## $u:" "$STORIES_MD"; then problems="${problems}NO_STORY:$u "; fi
      done
    fi

    # 4. tests referenced (best-effort: final symbol name, first 3)
    if [ -n "$tests" ]; then
      n=0
      IFS=',' read -ra TESTS <<< "$tests"
      for t in "${TESTS[@]}"; do
        [ $n -ge 3 ] && break
        t_trim="$(echo "$t" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -z "$t_trim" ] && continue
        t_sym="${t_trim##*::}"
        if ! echo "$t_trim" | grep -q " "; then
          if ! grep -rq -- "$t_sym" "$ROOT/src" "$ROOT/apps" "$ROOT/packages" "$ROOT/tests" 2>/dev/null; then
            problems="${problems}NO_TEST_REF:$t_trim "
          fi
        fi
        n=$((n+1))
      done
    fi

    if [ -z "$problems" ]; then
      PASS=$((PASS+1)); verdict="PASS"
    else
      FAIL=$((FAIL+1)); FAILED+=("$fid: $problems"); verdict="FAIL"
    fi
    if [ "$DO_JSON" -eq 0 ]; then
      printf "%-38s %5s%%  %s\n" "$fid" "$pct" "$verdict"
      [ -n "$problems" ] && printf "       ⚠ %s\n" "$problems"
    fi
  done < <("$PYTHON" "$EXTRACT_PY" "$FEATURES_JSON")
else
  echo "Skipping feature checks (no features.json)."
fi

# ---------------------------------------------------------------------------
# 5. Build / compile (optional)
# ---------------------------------------------------------------------------
BUILD_STATUS="skipped"
if [ "$DO_CHECK" -eq 1 ]; then
  echo ""
  echo "── build ($STACK) ───────────────────────────────────"
  case "$STACK" in
    rust)
      if (cd "$ROOT" && CARGO_TARGET_DIR=/build/rust-target/verify cargo check --workspace 2>&1 | tail -3); then BUILD_STATUS="ok"; else BUILD_STATUS="FAILED"; fi ;;
    anchor)
      # Anchor monorepo (gara-g): check Rust programs in programs/, fallback to root npm build
      if (cd "$ROOT/programs" && CARGO_TARGET_DIR=/build/rust-target/verify cargo check --workspace 2>&1 | tail -3); then BUILD_STATUS="ok (cargo)"
      elif (cd "$ROOT" && npm run build 2>&1 | tail -3); then BUILD_STATUS="ok (npm)"
      else BUILD_STATUS="FAILED"; fi ;;
    pnpm)
      if (cd "$ROOT" && pnpm build 2>&1 | tail -3); then BUILD_STATUS="ok"; else BUILD_STATUS="FAILED"; fi ;;
    npm)
      if (cd "$ROOT" && npm run build 2>&1 | tail -3); then BUILD_STATUS="ok"; else BUILD_STATUS="FAILED"; fi ;;
    *)
      # fallback: try generic build script
      if (cd "$ROOT" && npm run build 2>&1 | tail -3); then BUILD_STATUS="ok"; else BUILD_STATUS="no-build-script"; fi ;;
  esac
fi

# ---------------------------------------------------------------------------
# 6. Tests (optional)
# ---------------------------------------------------------------------------
TEST_STATUS="skipped"
if [ "$DO_TEST" -eq 1 ]; then
  echo ""
  echo "── tests ($STACK) ───────────────────────────────────"
  case "$STACK" in
    rust)
      if (cd "$ROOT" && CARGO_TARGET_DIR=/build/rust-target/verify cargo test --workspace 2>&1 | tail -5); then TEST_STATUS="ok"; else TEST_STATUS="FAILED"; fi ;;
    anchor)
      # Anchor: cargo test programs + root mocha suite
      if (cd "$ROOT/programs" && CARGO_TARGET_DIR=/build/rust-target/verify cargo test --workspace 2>&1 | tail -5) && (cd "$ROOT" && npm test 2>&1 | tail -3); then TEST_STATUS="ok"
      else TEST_STATUS="FAILED"; fi ;;
    pnpm)
      if (cd "$ROOT" && pnpm test 2>&1 | tail -5); then TEST_STATUS="ok"; else TEST_STATUS="FAILED"; fi ;;
    npm)
      # worldexams-style: canonical validation is `npm run validate`
      if (cd "$ROOT" && npm test 2>&1 | tail -5); then TEST_STATUS="ok"
      elif (cd "$ROOT" && npm run validate 2>&1 | tail -5); then TEST_STATUS="ok (validate)"
      else TEST_STATUS="FAILED"; fi ;;
    *) TEST_STATUS="no-test-script" ;;
  esac
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
if [ "$DO_JSON" -eq 1 ]; then
  FAILED_JSON="["
  if [ ${#FAILED[@]} -gt 0 ]; then
    for f in "${FAILED[@]}"; do FAILED_JSON="${FAILED_JSON}\"${f%%:*}\","; done
    FAILED_JSON="${FAILED_JSON%,}"
  fi
  FAILED_JSON="${FAILED_JSON}]"
  "$PYTHON" - "$FAILED_JSON" "$BUILD_STATUS" "$TEST_STATUS" "$TOTAL" "$PASS" "$STACK" <<'PYEOF'
import json, sys
failed = json.loads(sys.argv[1])
total, passed = int(sys.argv[4]), int(sys.argv[5])
print(json.dumps({
  'project': 'generic',
  'generated_at': __import__('datetime').date.today().isoformat(),
  'stack': sys.argv[6],
  'total': total, 'pass': passed, 'fail': total - passed,
  'failed': failed,
  'build': sys.argv[2],
  'test': sys.argv[3]
}, indent=2))
PYEOF
else
  echo ""
  echo "══════════════════════════════════════════════════════════"
  echo " Pipeline result: $PASS/$TOTAL features verified   (FAIL=$FAIL)   [stack: $STACK]"
  echo " build: $BUILD_STATUS   test: $TEST_STATUS"
  echo "══════════════════════════════════════════════════════════"
  if [ ${#FAILED[@]} -gt 0 ]; then
    printf '%s\n' "${FAILED[@]}" | sed 's/^/  ❌ /'
    exit 1
  fi
fi
exit 0
