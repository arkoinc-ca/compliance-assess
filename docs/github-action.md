# GitHub Action

Integrate compliance-assess into your GitHub Actions CI workflow in minutes.

## Quick Add

Add this step to your workflow:

```yaml
name: Compliance scan
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: arkoinc-ca/compliance-assess@v0.2
        with:
          profile: profiles/region/ca-on.yaml
```

This runs a scan against your repository with the Ontario (PIPEDA + CASL) profile and uploads SARIF to GitHub Code Scanning.

## Inputs

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `target` | Path to directory to scan, relative to repository root | false | `.` |
| `profile` | Path to profile YAML (e.g., `profiles/region/ca-on.yaml`) | true | — |
| `catalog` | Path to compliance-catalog root or `pip` to install from PyPI | false | `pip` |
| `catalog-version` | When `catalog=pip`, the version specifier (e.g., `0.1.0`, `>=0.1,<0.2`) | false | `>=0.1,<0.2` |
| `format` | Comma-separated output formats: sarif, markdown, html, csv | false | `sarif,markdown` |
| `output-dir` | Directory to write reports into | false | `compliance-reports` |
| `upload-sarif` | If `true`, upload SARIF to GitHub Code Scanning | false | `true` |
| `fail-on-high` | If `true`, exit 1 when any high-severity or critical finding is produced | false | `true` |

## Outputs

| Name | Description |
|------|-------------|
| `sarif-path` | Absolute path to generated SARIF file (if created) |
| `findings-count` | Total number of findings |
| `high-findings-count` | Number of high-severity and critical findings |

## Common Configurations

**Use a local catalog checkout:**

```yaml
- uses: actions/checkout@v4
  with:
    repository: arkoinc-ca/compliance-catalog
    path: compliance-catalog

- uses: arkoinc-ca/compliance-assess@v0.2
  with:
    profile: profiles/region/ca-on.yaml
    catalog: ./compliance-catalog
```

**Use a use-case profile:**

```yaml
- uses: arkoinc-ca/compliance-assess@v0.2
  with:
    profile: profiles/use-case/saas-canada-b2c.yaml
```

**Suppress high-severity gating:**

```yaml
- uses: arkoinc-ca/compliance-assess@v0.2
  with:
    profile: profiles/region/ca-on.yaml
    fail-on-high: 'false'
```

**Skip SARIF upload:**

```yaml
- uses: arkoinc-ca/compliance-assess@v0.2
  with:
    profile: profiles/region/ca-on.yaml
    upload-sarif: 'false'
```

## Permissions Required

- `contents: read` — always required (to read your code)
- `security-events: write` — only required if `upload-sarif: true`

## Reading the SARIF Tab

After a workflow run completes, navigate to the **Security** tab in your repository. Click **Code scanning alerts** to view findings grouped by rule, severity, and file. Each alert links to the affected line and includes remediation guidance.

The tool name is `compliance-assess`. Filter by tool, severity, or file path.

## Caveats

The action references `github.action_ref` to auto-install the matching version of compliance-assess from PyPI. If you pin the action to a specific commit SHA (e.g., `@abc123def`), manually ensure the SHA corresponds to a published version on PyPI:

```bash
python -m pip install compliance-assess==0.2.0  # or use github.action_ref
```

Catalog version defaults to `>=0.1,<0.2`. Adjust `catalog-version` if v1.0.0 is released and you want to track it.

<!-- written-by: writer-haiku | model: haiku -->
