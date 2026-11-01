# Anthropic's claude-code-security-review pinned for the M8 competitive run; keys arrive only at run time (see run.sh).
FROM node:22-bookworm-slim AS node

FROM python:3.11-slim-bookworm

ARG CCSR_REPO=https://github.com/anthropics/claude-code-security-review
ARG CCSR_SHA=0c6a49f1fa56a1d472575da86a94dbc1edb78eda
ARG CLAUDE_CODE_VERSION=2.1.316

# Claude Code 2.x needs Node 22+.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates \
 && mkdir -p -m 755 /etc/apt/keyrings \
 && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
 && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends gh \
 && rm -rf /var/lib/apt/lists/*

RUN git clone "$CCSR_REPO" /opt/ccsr \
 && git -C /opt/ccsr checkout --detach "$CCSR_SHA" \
 && test "$(git -C /opt/ccsr rev-parse HEAD)" = "$CCSR_SHA" \
 && pip install --no-cache-dir -r /opt/ccsr/claudecode/requirements.txt \
 && pip freeze > /opt/ccsr/pip-freeze.txt

RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && claude --version \
 && claude --help | grep -q -- '--max-budget-usd'

# The cost guard shadows the real CLI on PATH; github_action_audit.py calls plain `claude`.
COPY claude-guard.sh /opt/guard/claude
COPY run.sh /opt/run.sh
RUN chmod 755 /opt/guard/claude /opt/run.sh

ENV PATH=/opt/guard:$PATH \
    CCSR_SHA=$CCSR_SHA \
    CLAUDE_CODE_VERSION=$CLAUDE_CODE_VERSION \
    CLAUDE_MODEL=claude-opus-5-5 \
    COMPETITOR_MAX_CALLS=1 \
    COMPETITOR_MAX_TURNS=60 \
    COMPETITOR_MAX_BUDGET_USD=4 \
    DISABLE_TELEMETRY=1 \
    DISABLE_ERROR_REPORTING=1 \
    DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/ccsr
ENTRYPOINT ["/opt/run.sh"]
