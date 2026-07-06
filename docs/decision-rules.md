# culler Decision Rules

culler assigns every finding to one of four remediation tiers using a transparent, ordered rule tree.

## Rule Tree

```
Finding
 │
 ├─ in CISA KEV?
 │   └─ yes → ACT NOW  (ransomware-linked highlighted)
 │
 ├─ EPSS ≥ 0.088 OR SSVC Exploitation = active?
 │   └─ yes → OUT-OF-CYCLE
 │
 ├─ EPSS percentile ≥ 90%  OR  (CVSS ≥ 7.0 AND SSVC Automatable = yes)?
 │   └─ yes → SCHEDULED
 │
 └─ else → DEFER
```

Rules are evaluated in order; the first match wins.

## Tiers Explained

| Tier | Meaning | Default SLA |
|------|---------|-------------|
| **ACT NOW** | Actively exploited in the wild (KEV). Fix or mitigate immediately. | 24 h |
| **OUT-OF-CYCLE** | High exploitation probability (EPSS ≥ 8.8%) or confirmed active exploitation (SSVC). Fix at next opportunity, don't wait for the sprint cycle. | 7 days |
| **SCHEDULED** | Elevated risk warrants attention in the normal release cycle. | 30 days |
| **DEFER** | Low exploitation probability. Track and reassess. | 90 days |

## Data Sources

| Source | What it provides | Update frequency |
|--------|-----------------|-----------------|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed in-the-wild exploitation | Updated continuously |
| [FIRST EPSS](https://www.first.org/epss/) | Probability of exploitation in next 30 days | Daily |
| [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) | SSVC decision points + ADP CVSS scores | Continuous |
| NVD / CNA | CVSS base scores | Varies |

## CVSS Provenance Fallback Chain

When NVD lacks CVSS data (common for CVEs < 90 days old since April 2026):

```
scanner-provided → NVD (if NVD API key supplied) → CNA/ADP via Vulnrichment → GHSA/OSV severity
```

Every score is labelled with its source (`nvd`, `cna`, `scanner`, `ghsa`).

## Configurable Thresholds

Defaults can be overridden in `.culler.yaml`:

```yaml
thresholds:
  epss_out_of_cycle: 0.088   # default
  epss_percentile:   0.90    # default
  cvss_scheduled:    7.0     # default
```

## Limitations

- EPSS scores are based on historical exploitation patterns and lag brand-new CVEs by days to weeks.
- KEV is not exhaustive — absence from KEV does not mean a CVE is unexploited.
- SSVC data is available for a subset of CVEs (those with Vulnrichment entries).
- culler is decision **support**, not a guarantee. Review output critically.
