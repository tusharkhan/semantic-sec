# Technical Specification: Semantic Security & Vulnerability Analyzer for PHP

## 1. Project Overview & Purpose

This project is a standalone CLI-based Static Application Security Testing (SAST) tool for PHP. 

**The Problem:** Traditional static analyzers (PHPStan, Psalm) and security scanners (PHP_CodeSniffer) rely on hardcoded rules and regex. They easily catch syntax errors and basic SQLi, but are completely blind to contextual business logic flaws, such as authorization bypasses (IDOR), improper state transitions, or missing ownership checks.
**The Solution:** An analyzer that uses an Abstract Syntax Tree (AST) to extract execution paths and feeds them to a Large Language Model (LLM) tailored for cybersecurity. 
**The Outcome:** A tool that acts as an automated security researcher, understanding the *intent* of the PHP code to find complex logical vulnerabilities before they reach production.

## 2. Core Data Flow & Execution Lifecycle

To prevent token limits from being exceeded and to reduce API costs, the package cannot simply send entire files to the LLM. It must intelligently compress the codebase.

1. **AST Parsing:** The tool parses target PHP directories using an AST library (e.g., `nikic/php-parser`).
2. **Contextual Pruning:** It strips out low-risk code (docblocks, getters/setters, interfaces) and isolates high-risk areas (Controllers, Repositories, Services).
3. **Graph Construction (Execution Path):** It maps method calls. If `CheckoutController::process()` calls `PaymentService::charge()`, the tool merges these AST nodes into a single payload so the LLM has the full execution context.
4. **LLM Evaluation:** The compressed code blocks are sent to an LLM via API, utilizing a strict System Prompt trained on the OWASP Top 10 and PHP-specific security pitfalls.
5. **Structured Output:** The LLM is forced to return JSON. The CLI tool maps this JSON to terminal output or a standard SARIF file for CI/CD integration.

## 3. Directory Structure (PSR-4)

```text
src/
├── Console/
│   ├── AnalyzeCommand.php     # Entry point (e.g., vendor/bin/semantic-sec)
│   └── Formatters/            # Handles output (ConsoleFormatter, JsonFormatter, SarifFormatter)
├── Parsing/
│   ├── AstGenerator.php       # Wrapper for nikic/php-parser
│   ├── CallGraphBuilder.php   # Traces execution paths across files
│   └── Pruner.php             # Removes irrelevant tokens to save LLM context window
├── LLM/
│   ├── ClientInterface.php    # Interface for AI APIs
│   ├── OpenAiClient.php       
│   ├── SystemPrompts/         # Strictly crafted prompts for security analysis
│   └── ResponseValidator.php  # Ensures LLM output matches the required JSON schema
├── Analysis/
│   ├── Vulnerability.php      # Value object representing a found flaw (Title, Severity, Line, Fix)
│   └── Engine.php             # Orchestrates the Pipeline: Parse -> Prune -> LLM -> Validate
└── Rulesets/
    ├── BasePhpContext.php     # Teaches LLM about native PHP dangers (unserialize, exec)
    ├── LaravelContext.php     # Framework context (Eloquent IDORs, Mass Assignment)
    └── SymfonyContext.php     # Framework context (Security Voters, Request injection)
```

## 4. The Developer Experience (CLI Usage)

The package is installed as a development dependency and executed via the command line.

**Execution Command:**
```bash
vendor/bin/semantic-sec analyze app/Http/Controllers/ --framework=laravel --level=high --format=console
```

**Expected Terminal Output:**
```text
[!] High Severity: Insecure Direct Object Reference (IDOR)
File: app/Http/Controllers/BillingController.php
Line: 45

Context: 
The method `updateBilling(Request $request, $id)` updates a record using `$id` directly from the route parameters. 

Flaw: 
There is no authorization check to verify that the currently authenticated user (`auth()->user()`) actually owns the billing record associated with `$id`. An attacker can iterate through IDs to modify other users' data.

Suggested Fix: 
Scope the database query to the authenticated user's relationship:
- $billing = Billing::findOrFail($id);
+ $billing = auth()->user()->billingRecords()->findOrFail($id);
```

## 5. Architectural Requirements for the LLM Generating This Code

1. **Standalone CLI:** Use `symfony/console` as the base for building the CLI commands. It provides robust input/output handling.
2. **AST Dependency:** Rely on `nikic/php-parser` for reading the PHP code. Do not attempt to use regex for code extraction.
3. **Structured Prompts:** The `SystemPrompts` classes must explicitly instruct the LLM to ignore stylistic issues and focus *only* on security vulnerabilities. 
4. **JSON Schema Enforcement:** The `ResponseValidator` is critical. LLMs can hallucinate formatting. You must pass a strict JSON Schema to the LLM (using OpenAI's Structured Outputs feature if available) to ensure the CLI tool doesn't crash when parsing the response into the `Vulnerability` object.
5. **CI/CD Readiness:** The `Formatters\SarifFormatter` must output valid SARIF v2.1.0 JSON so GitHub Actions and GitLab CI can automatically annotate pull requests with the findings.