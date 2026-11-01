#!/bin/bash
# Usage: docker run --rm --env-file .env.live -e GITHUB_TOKEN -v "$OUT:/out" semsec-competitor:m8 owner/repo#N
set -euo pipefail

PR="${1:?usage: run.sh owner/repo#N}"
OUT=/out
mkdir -p "$OUT" /work

# --env-file keeps quotes literally; strip one matching pair, never print the value.
for name in ANTHROPIC_API_KEY GITHUB_TOKEN; do
  value="${!name:-}"
  if [ -z "$value" ]; then
    echo "run.sh: $name is not set" >&2
    exit 2
  fi
  case "$value" in
    \"*\") value="${value#\"}"; value="${value%\"}" ;;
    \'*\') value="${value#\'}"; value="${value%\'}" ;;
  esac
  export "$name=$value"
done
export GH_TOKEN="$GITHUB_TOKEN"

# Git reads the token from the environment at call time, so it never lands in a URL, a log or .git/config.
git config --global credential.helper '!f() { echo username=x-access-token; echo "password=$GITHUB_TOKEN"; }; f'
git config --global user.email competitor@example.invalid
git config --global user.name competitor

# Pre-clone without the token in the URL; the eval engine reuses this checkout instead of cloning with https://TOKEN@.
REPO="${PR%%#*}"
BASE="/work/${REPO//\//_}"
if [ ! -d "$BASE" ]; then
  git clone --quiet --filter=blob:none "https://github.com/$REPO.git" "$BASE"
fi

rm -f "$OUT/.claude-calls" "$OUT"/claude-call-*.json
cat > "$OUT/run-meta.json" <<JSON
{
  "sha": "$(git -C /opt/ccsr rev-parse HEAD)",
  "claudeCode": "$(/usr/local/bin/claude --version | head -n1)",
  "model": "${CLAUDE_MODEL}",
  "pr": "$PR",
  "limits": "at most ${COMPETITOR_MAX_CALLS} Claude Code calls, ${COMPETITOR_MAX_TURNS} turns and \$${COMPETITOR_MAX_BUDGET_USD} each",
  "started": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

# Mask both secrets in anything the tool prints, belt and braces.
mask() {
  python3 -c '
import os, sys
secrets = [s for s in (os.environ.get("ANTHROPIC_API_KEY"), os.environ.get("GITHUB_TOKEN")) if s]
for line in sys.stdin:
    for s in secrets:
        line = line.replace(s, "***")
    sys.stdout.write(line)
    sys.stdout.flush()
'
}

set +e
python -m claudecode.evals.run_eval "$PR" --output-dir "$OUT" --work-dir /work --verbose 2>&1 | mask
status=${PIPESTATUS[0]}
set -e

if [ -f "$OUT/pr_${REPO//\//_}_${PR##*#}.json" ]; then
  cp "$OUT/pr_${REPO//\//_}_${PR##*#}.json" "$OUT/eval_results.json"
fi
echo "run.sh: eval exited $status; Claude Code calls: $(cat "$OUT/.claude-calls" 2>/dev/null || echo 0); results in $OUT" >&2
exit "$status"
