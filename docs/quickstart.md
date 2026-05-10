# Quickstart

Get your first compliance scan running in under 20 minutes.

## Prerequisites

- Python 3.11 or later
- git
- pip (or uv)
- Optional: semgrep CLI for offline static-analysis support

## Install

Install from PyPI:

```bash
pip install compliance-assess compliance-catalog
```

Or install from source for development:

```bash
git clone https://github.com/arkoinc-ca/compliance-assess.git
cd compliance-assess
pip install -e .
pip install compliance-catalog
```

## Pick a Profile

Profiles define which controls to assess. Two profile types are available in the catalog:

**Region profiles** (`profiles/region/`): jurisdiction-specific control sets — e.g., `ca-on.yaml` (Ontario: PIPEDA + CASL), `eu-generic.yaml` (GDPR + ePrivacy Directive).

**Use-case profiles** (`profiles/use-case/`): industry or SaaS pattern — e.g., `saas-canada-b2c.yaml` (B2C SaaS operating in Canada).

Browse available profiles:

```bash
compliance-assess profile list --catalog ./compliance-catalog
```

Output shows profile path, title, and control count. Pick one that matches your jurisdiction and application type.

## Run a Scan

Scan your codebase against a profile:

```bash
compliance-assess scan ./my-app \
  --profile profiles/region/ca-on.yaml \
  --catalog ./compliance-catalog \
  --format sarif,markdown
```

Command flags:

- `target` (positional): path to directory to scan
- `--profile` / `-p`: path to profile YAML (required)
- `--catalog`: path to compliance-catalog root; defaults to `../compliance-catalog`
- `--format`: comma-separated output formats (sarif, markdown, html, csv); default is `sarif,markdown`
- `--out`: output directory for reports; defaults to current directory
- `--timeout`: per-scan timeout in seconds; default 30.0

## Interpret the Output

The scan prints a summary to stdout:

```
Profile:            Canada — Ontario Region Profile (PIPEDA + CASL)
Target:             ./my-app
Controls assessed:  18
Controls with findings: 5
Total findings:     12
  high: 4
  medium: 5
  low: 3
```

Then generates reports in the output directory:

**SARIF** (`compliance-assessment.sarif`): machine-readable format compatible with GitHub Code Scanning and VS Code SARIF Viewer. Each finding includes location, severity, rule ID, and remediation guidance.

**Markdown** (`compliance-assessment.md`): human-readable report grouped by control, with PII-safe summaries and links to affected files.

## Exit Codes

- **0**: Clean scan — no high or critical severity findings
- **1**: One or more high or critical severity findings detected
- **2**: Scan partially failed — one or more engines encountered an error (e.g. semgrep timeout, JSON parse failure). Results may be incomplete. Treat exit 2 as a warning; review logs and re-run.

Exit code 1 signals CI/CD gating; include the scan in your pull-request workflow to enforce compliance gates. Exit code 2 indicates infrastructure issues — do not treat it as a passing scan.

## Next Steps

- **Integrate into GitHub Actions**: see `github-action.md`
- **Understand rule precision**: see `rule-precision.md`
- **Check language support**: see `supported-languages.md`

Example sample app (for testing): `tests/fixtures/sample-app/`

<!-- written-by: writer-haiku | model: haiku -->
