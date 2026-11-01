#!/bin/bash
# Cost guard in front of the real Claude Code CLI: caps calls, turns and dollars per call, and keeps each call's JSON.
set -uo pipefail
REAL=/usr/local/bin/claude
OUT=${COMPETITOR_OUT:-/out}

case "${1:-}" in
  --version|-v|--help|-h) exec "$REAL" "$@" ;;
esac

COUNT_FILE="$OUT/.claude-calls"
n=$(( $(cat "$COUNT_FILE" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$COUNT_FILE"
if [ "$n" -gt "${COMPETITOR_MAX_CALLS:-1}" ]; then
  echo "cost guard: Claude Code call $n refused (COMPETITOR_MAX_CALLS=${COMPETITOR_MAX_CALLS:-1})" >&2
  exit 1
fi

echo "cost guard: call $n, --max-turns ${COMPETITOR_MAX_TURNS:-60}, --max-budget-usd ${COMPETITOR_MAX_BUDGET_USD:-4}, model in args: $*" >&2
"$REAL" --max-turns "${COMPETITOR_MAX_TURNS:-60}" --max-budget-usd "${COMPETITOR_MAX_BUDGET_USD:-4}" "$@" | tee "$OUT/claude-call-$n.json"
exit "${PIPESTATUS[0]}"
