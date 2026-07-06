# culler

**Vulnerability triage engine** — cut through scanner noise and focus on what actually needs fixing.

[![CI](https://github.com/sumeetghimire/culler/actions/workflows/ci.yml/badge.svg)](https://github.com/sumeetghimire/culler/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/sumeetghimire/culler)](https://goreportcard.com/report/github.com/sumeetghimire/culler)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## Install

**One-liner (Linux / macOS)**
```sh
curl -sSL https://raw.githubusercontent.com/sumeetghimire/culler/main/install.sh | sh
```

**Homebrew**
```sh
brew install sumeetghimire/tap/culler
```

**Go**
```sh
go install github.com/sumeetghimire/culler/cmd/culler@latest
```

**Docker**
```sh
docker run --rm -i ghcr.io/sumeetghimire/culler < report.json
```

---

## Quickstart

```sh
# Pipe Grype output straight in — no flags needed
grype dir:. -o json | culler
```

```
culler: loading threat-intel feeds...
culler: KEV 1631 entries · EPSS 345694 entries · Vulnrichment (per-CVE)
10 findings → 4 ACT NOW · 4 OUT-OF-CYCLE · 2 SCHEDULED · 0 DEFER

CVE/ID          PACKAGE            VERSION   FIX       EPSS           KEV    TIER  WHY
──────────────  ─────────────────  ────────  ────────  ─────────────  ─────  ────  ──────────────────────────────────
CVE-2021-44228  log4j-core         2.14.1    2.15.0    1.0000 (100%)  KEV✓   NOW   in CISA KEV (added 2021-12-10) [ransomware-linked]
CVE-2022-22965  spring-webmvc      5.3.16    5.3.18    0.9968 (99%)   KEV✓   NOW   in CISA KEV (added 2022-04-04)
CVE-2023-44487  tomcat-embed-core  9.0.70    2.7.18    1.0000 (99%)   KEV✓   NOW   in CISA KEV (added 2023-10-10)
CVE-2022-42889  commons-text       1.9       1.10.0    0.9993 (99%)          OOC   EPSS 0.9993 ≥ 0.088 threshold
CVE-2022-1471   snakeyaml          1.30      2.0       0.9961 (99%)          OOC   EPSS 0.9961 ≥ 0.088 threshold
CVE-2021-3156   sudo               1.8.31    1.9.5p2   0.9929 (99%)   KEV✓   NOW   in CISA KEV (added 2022-04-06)
CVE-2021-29425  commons-io         2.6       2.7       0.1061 (95%)          OOC   EPSS 0.1061 ≥ 0.088 threshold
CVE-2022-25647  gson               2.8.6     2.8.9     0.1158 (95%)          OOC   EPSS 0.1158 ≥ 0.088 threshold

2 SCHEDULED and 0 DEFER findings hidden. Use --all to show all.

Note: EPSS scores lag new exploits by days–weeks. KEV is not exhaustive.
```

---

## Why now?

In April 2026, NIST transitioned NVD analysis to a new triage process, leaving thousands of CVEs without CVSS scores or CPE data for weeks. Meanwhile CVE volume has grown past 40,000/year. **You cannot manually triage every finding**.

culler solves this by layering three free, real-time signals:

1. **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — confirmed active exploitation
2. **[FIRST EPSS](https://www.first.org/epss/)** — probability of exploitation in the next 30 days
3. **[CISA Vulnrichment](https://github.com/cisagov/vulnrichment)** — SSVC decision points + ADP CVSS when NVD is blank

The result: 400 findings collapse to a short, prioritized, *explainable* queue.

---

## Decision Rules

```
In CISA KEV                              → ACT NOW       (fix within 24 h)
EPSS ≥ 8.8% OR SSVC Exploitation=active → OUT-OF-CYCLE  (fix within 7 days)
EPSS ≥ 90th pct OR CVSS ≥ 7.0           → SCHEDULED     (fix in sprint cycle)
Everything else                          → DEFER
```

See [docs/decision-rules.md](docs/decision-rules.md) for full documentation including configurable thresholds.

---

## CLI Reference

```sh
# Scan from stdin (default)
grype dir:. -o json | culler
trivy fs --format json . | culler

# Scan a file
culler scan report.json --all
culler scan report.json --format markdown --output report.md

# Output formats
culler scan report.json --format json        # machine-readable with full provenance
culler scan report.json --format sarif       # upload to GitHub Code Scanning
culler scan report.json --format markdown    # paste into PR comments

# Explain a specific CVE (uses last scan)
culler explain CVE-2021-44228

# CI gate — exit 1 if any ACT NOW findings
culler scan report.json --fail-on act-now

# Offline mode (use cached feeds)
culler scan report.json --offline

# Refresh feeds
culler update

# Feed ages
culler version
```

---

## GitHub Action (CI Integration)

```yaml
- name: Grype scan
  uses: anchore/scan-action@v3
  with:
    path: "."
    output-format: json
    output-file: grype.json
  continue-on-error: true

- name: culler triage
  uses: sumeetghimire/culler/action@v1
  with:
    scanner-output: grype.json
    format: sarif
    output-file: culler.sarif
    fail-on: act-now

- name: Upload to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: culler.sarif
```

---

## Policy File

Create `.culler.yaml` to customise behaviour:

```yaml
internet_facing: true  # bump all findings one tier

ignore:
  - id: CVE-2021-29425
    reason: "Path traversal not reachable via external inputs"
    expires: "2025-12-01"

thresholds:
  epss_out_of_cycle: 0.05   # be more aggressive
```

See [docs/policy.md](docs/policy.md) for full reference.

---

## Supported Scanners

| Scanner | How to generate input |
|---------|----------------------|
| [Grype](https://github.com/anchore/grype) | `grype dir:. -o json` |
| [Trivy](https://github.com/aquasecurity/trivy) | `trivy fs --format json .` |
| [OSV-Scanner](https://github.com/google/osv-scanner) | `osv-scanner --format json .` |
| CycloneDX SBOM | `cdxgen -o sbom.json` (then `culler scan sbom.json`) |

Format is auto-detected — no flag needed.

---

## Limitations / Disclaimer

- EPSS scores are probabilistic and lag new exploitation by days to weeks.
- KEV is not exhaustive — absence from KEV does not mean a CVE is safe.
- SSVC data is only available for CVEs with Vulnrichment entries (~60% of KEV CVEs).
- culler is **decision support**, not a guarantee. Apply judgement.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs welcome.

## License

Apache 2.0 — see [LICENSE](LICENSE).
