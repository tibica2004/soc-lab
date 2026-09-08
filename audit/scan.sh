#!/usr/bin/env bash
set -euo pipefail
: "${TARGET:?Seteaza TARGET = calea absoluta catre codul sursa}"
OUT="${1:-$PWD/out}"
mkdir -p "$OUT"

command -v semgrep >/dev/null || { echo "semgrep lipseste"; exit 2; }
test -d "$TARGET" || { echo "TARGET inexistent: $TARGET"; exit 2; }

CONFIGS=(
  --config=p/security-audit
  --config=p/owasp-top-ten
  --config=p/secrets
  --config=p/python
)

echo ">> Semgrep pe $TARGET"
set +e
semgrep scan "${CONFIGS[@]}" \
  --sarif --output "$OUT/semgrep.sarif" \
  --metrics=off --timeout 30 --max-target-bytes 2000000 "$TARGET"
rc=$?
set -e
[ "$rc" -gt 1 ] && { echo "Semgrep a esuat (exit $rc)"; exit "$rc"; }

if [ -f "$OUT/semgrep.sarif" ]; then
  n=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(sum(len(r.get('results',[])) for r in d.get('runs',[])))" "$OUT/semgrep.sarif")
  echo "   findings: $n  ->  $OUT/semgrep.sarif"
fi
