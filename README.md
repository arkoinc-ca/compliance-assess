# compliance-assess

Static and runtime assessor that scans codebases for privacy, AI governance, and anti-spam compliance gaps; emits OSCAL Assessment Results, SARIF, and Markdown findings.

![Status](https://img.shields.io/badge/status-v0%20pre--release-orange)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

> **v0 — pre-release; library + CLI target Phase 2, target Sep 2026**

---

> **DISCLAIMER**
>
> This toolkit is software. It identifies potential compliance gaps in code and provides runtime technical controls. It does **not** constitute legal advice and does not guarantee regulatory compliance. It does not appoint Data Protection Officers, execute Data Processing Agreements, conduct Privacy Impact Assessments, certify compliance with any law or standard, or replace organizational policy, legal counsel, staff training, or incident response processes.
>
> Compliance with applicable laws — including but not limited to PIPEDA, Quebec Law 25, GDPR, CCPA/CPRA, CASL, and applicable AI regulations — is the responsibility of your organization and its qualified advisors. Outputs from this toolkit are technical findings, not legal determinations. Always engage qualified legal counsel for compliance decisions.

---

## What it does

`compliance-assess` scans a codebase or running service and produces machine-readable reports of compliance gaps against a selected jurisdiction profile.

**Static analysis** (via [semgrep](https://semgrep.dev/) and [tree-sitter](https://tree-sitter.github.io/tree-sitter/)):
- PII appearing in log statements
- Missing consent-check guard clauses before data collection
- Absent or misrouted data-subject-request (DSR) handler endpoints
- Missing audit-event emission around sensitive operations
- High-risk AI decision paths without documented accuracy or robustness tests

**Runtime probes** (via [OpenTelemetry](https://opentelemetry.io/)):
- Retention window violations detected from trace metadata
- PII flow reconstruction across service boundaries
- Undocumented third-party data egress

**Outputs:**
- OSCAL Assessment Results (YAML)
- SARIF 2.1.0 (compatible with GitHub Code Scanning, VS Code SARIF Viewer)
- Markdown findings report (human-readable summary)

---

## Architecture

```
compliance-assess
├── CLI (click / argparse)
│   └── assess scan | assess report | assess validate
├── Core library
│   ├── scanner/           # Semgrep + tree-sitter orchestration
│   ├── probes/            # OpenTelemetry trace ingestion
│   ├── catalog_loader/    # Reads compliance-catalog OSCAL files
│   └── findings/          # Finding model, deduplication, severity
└── Output adapters
    ├── oscal_writer/      # OSCAL Assessment Results
    ├── sarif_writer/      # SARIF 2.1.0
    └── markdown_writer/   # Markdown report
```

---

## Planned distribution

| Channel | Identifier |
|---------|-----------|
| PyPI | `compliance-assess` |
| Docker | `ghcr.io/arkoinc-ca/compliance-assess:latest` |
| GitHub Action | `arkoinc-ca/compliance-assess-action` |

---

## Phase 2 scope and status

See [`docs/phases/phase-2-assessor-v0.md`](../../docs/phases/phase-2-assessor-v0.md) for the full task list and acceptance gates.

- [ ] Semgrep rule authoring (PIPEDA, Law 25, GDPR, CCPA/CPRA, CASL)
- [ ] OSCAL Assessment Results writer
- [ ] SARIF writer with SARIF schema validation
- [ ] Markdown report writer
- [ ] CLI (`assess scan`, `assess report`)
- [ ] Docker image build and GHCR publish
- [ ] GitHub Action wrapper
- [ ] Integration tests against a controlled test corpus
- [ ] PyPI publish (pre-release)

---

## License

Licensed under [Apache-2.0](LICENSE). You may use, modify, and distribute this software under the terms of the Apache License, Version 2.0. The control catalog it consumes is separately licensed CC-BY-4.0 — see [`compliance-catalog`](https://github.com/arkoinc-ca/compliance-catalog).

<!-- written-by: builder-sonnet | model: sonnet -->
