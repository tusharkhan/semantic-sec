# semantic-sec

A CLI tool that finds authorization and business-logic vulnerabilities (such as IDOR) in Laravel applications. It parses the project to build an authorization map of routes and the checks that protect them, picks candidate routes that lack an ownership check, and can optionally ask an LLM to confirm each one.

Status: under development.

## Dry run

Pick candidate routes and write the payloads an LLM would get, without sending anything (no API key, no network):

```
vendor/bin/semantic-sec analyze --dry-run --project-root=/path/to/laravel-app
vendor/bin/semantic-sec analyze --dry-run --deep --format=json   # also review routes that have an authorization check
```

The system prompt lands in `.semantic-sec/dry-run/000-system.txt` and the payloads in `NNN-<verb-uri-slug>-<part>.txt` beside it, inside the project, secrets redacted. `semantic-sec map` prints the authorization map on its own.

## Groq

Groq speaks the OpenAI Chat Completions API, so it is not a separate provider. Point the `openai` provider at Groq's base URL in `semantic-sec.yaml`:

```yaml
provider: openai
base_url: https://api.groq.com/openai/v1
api_key_env: GROQ_API_KEY
model: openai/gpt-oss-120b
```

Put the key in your environment (`export GROQ_API_KEY=...`), never in the YAML. `api_key_env` names the variable; the key itself is never read from the config file.
