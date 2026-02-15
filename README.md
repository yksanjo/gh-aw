# gh-aw: GitHub Actions Workflow Security Scanner

A lightweight security scanner focused specifically on GitHub Actions workflows.

## Installation

```bash
pip install -r requirements.txt
# or just run directly - no dependencies needed!
```

## Usage

```bash
# Scan a workflow file
python3 scanner.py .github/workflows/

# JSON output
python3 scanner.py .github/workflows/ --json
```

## Features

- **Excessive Permissions Detection**: Detects overly permissive token settings
- **Unsafe Command Detection**: Finds dangerous shell commands
- **Secret Exposure Detection**: Identifies hardcoded secrets
- **Data Leakage Prevention**: Catches potential secret logging

## Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| PERM001 | HIGH | contents:write permission |
| PERM002 | CRITICAL | Admin permissions |
| PERM003 | CRITICAL | Secrets write access |
| PERM004 | CRITICAL | pull_request_target usage |
| EXEC001 | CRITICAL | rm -rf / |
| EXEC002 | CRITICAL | eval command |
| EXEC009 | CRITICAL | curl pipe sh |
| EXEC010 | CRITICAL | wget pipe sh |
| EXEC015 | CRITICAL | Privileged Docker |
| SECR002 | CRITICAL | GitHub PAT detected |
| SECR006 | CRITICAL | AWS Access Key |
| SECR007 | CRITICAL | OpenAI API Key |
| SECR010 | CRITICAL | Slack Token |
| DATA017 | HIGH | Secret logging |
| DATA018 | HIGH | HTTP (not HTTPS) |

## Example Output

```
🔍 gh-aw: GitHub Actions Security Scanner
   Files scanned: 3
   Findings: 5

[1] Overly Permissive GitHub Token (contents:write)
    Severity: HIGH
    File: .github/workflows/ci.yml
    Recommendation: Use 'contents: read' unless write access is required
```

## License

MIT
