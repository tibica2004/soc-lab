#!/usr/bin/env bash
#
# audit.sh — orchestratorul auditului. Asta pui in cron.
#   scan.sh (Semgrep) -> hunt.py (Antares) -> fuse.py
#
#   SKIP_ANTARES=1 ./audit.sh    doar Semgrep, fara model
#
set -euo pipefail
: "${TARGET:?Seteaza TARGET = calea absoluta catre codul sursa}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNS="${RUNS_ROOT:-$HERE/runs}"
BASELINE="${BASELINE_FILE:-$HERE/baseline.json}"
HYPOTHESES="${HYPOTHESES_FILE:-$HERE/hypotheses.txt}"
SKIP_ANTARES="${SKIP_ANTARES:-0}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN="$RUNS/$STAMP"
mkdir -p "$RUN"
[ -f "$BASELINE" ] || echo '[]' > "$BASELINE"

echo "=== Audit $STAMP ==="
echo "Target: $TARGET"
echo "Output: $RUN"
echo

SARIF_ARGS=()

echo "[1/3] Semgrep"
if TARGET="$TARGET" "$HERE/scan.sh" "$RUN"; then
  [ -f "$RUN/semgrep.sarif" ] && SARIF_ARGS+=(--sarif "semgrep=$RUN/semgrep.sarif")
else
  echo "   Semgrep a esuat — continui cu ce am."
fi
echo

echo "[2/3] Antares"
if [ "$SKIP_ANTARES" = "1" ]; then
  echo "   sarit (SKIP_ANTARES=1)"
elif ! curl -s --max-time 3 http://127.0.0.1:8000/health | grep -q '"status":"ok"'; then
  echo "   sarit: llama-server nu raspunde pe :8000"
else
  set +e
  python3 "$HERE/hunt.py" --repo "$TARGET" --out "$RUN" --hypotheses "$HYPOTHESES"
  rc=$?
  set -e
  [ "$rc" -ne 0 ] && echo "   hunt.py exit $rc — continui cu ce a produs."
  [ -f "$RUN/antares.sarif" ] && SARIF_ARGS+=(--sarif "antares=$RUN/antares.sarif")
fi
echo

echo "[3/3] Fuziune"
if [ "${#SARIF_ARGS[@]}" -eq 0 ]; then
  echo "   Nicio sursa SARIF. Opresc."
  exit 1
fi

python3 "$HERE/fuse.py" --repo "$TARGET" --out "$RUN" \
  --baseline "$BASELINE" "${SARIF_ARGS[@]}"

ln -sfn "$RUN" "$RUNS/latest"
echo
echo "Gata."
echo "  Triaj: $RUN/fused.md"
echo "  Ultima: $RUNS/latest"
