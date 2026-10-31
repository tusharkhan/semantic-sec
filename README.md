# semantic-sec

A CLI tool that finds authorization and business-logic vulnerabilities (such as IDOR) in Laravel applications. It parses the project to build an authorization map of routes and the checks that protect them, picks candidate routes that lack an ownership check, and can optionally ask an LLM to confirm each one.

Status: under development.

## Dry run

Pick candidate routes and write the payloads an LLM would get, without sending anything (no API key, no network):

```
vendor/bin/semantic-sec analyze --dry-run --project-root=/path/to/laravel-app
vendor/bin/semantic-sec analyze --dry-run --deep --format=json   # also review routes that have an authorization check
```

Payloads land in `.semantic-sec/dry-run/NNN-<verb-uri-slug>-<part>.txt` inside the project, secrets redacted. `semantic-sec map` prints the authorization map on its own.
