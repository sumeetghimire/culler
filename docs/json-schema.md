# culler JSON Output Schema

The `--format json` output follows this documented schema.

## Top-level object

| Field | Type | Description |
|-------|------|-------------|
| `$schema` | string | URL pointing to this document |
| `scan_time` | string (ISO 8601 UTC) | When the scan was run |
| `source` | string | Scanner that produced input: `grype`, `trivy`, `osv-scanner`, `cyclonedx` |
| `summary` | object | Tier counts (see below) |
| `findings` | array\<Finding\> | All findings after policy filtering, ordered as received |
| `warnings` | array\<string\> | Non-fatal issues (e.g., suppressed findings, stale feeds) |

## Summary object

| Field | Type | Description |
|-------|------|-------------|
| `total` | integer | Total finding count after policy filtering |
| `act_now` | integer | Findings at ACT NOW tier |
| `out_of_cycle` | integer | Findings at OUT-OF-CYCLE tier |
| `scheduled` | integer | Findings at SCHEDULED tier |
| `defer` | integer | Findings at DEFER tier |

## Finding object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | CVE ID (`CVE-YYYY-NNNNN`) or GHSA ID |
| `package` | string | Package name |
| `version` | string | Installed version |
| `ecosystem` | string | Package ecosystem: `go`, `npm`, `pypi`, `maven`, `gem`, `cargo`, `nuget`, `deb`, `rpm`, `apk` |
| `fixed_in` | array\<string\> | Versions where the vulnerability is fixed (may be empty) |
| `source` | string | Scanner source |
| `severity` | string | Raw severity string from scanner (e.g., `HIGH`), omitted if absent |
| `cvss` | CVSS object or null | CVSS data with provenance (null if unavailable) |
| `kev` | KEV object | CISA KEV membership data |
| `epss` | EPSS object | FIRST EPSS score |
| `ssvc` | SSVC object or null | CISA Vulnrichment SSVC decision points (null if unavailable) |
| `tier` | string | One of: `ACT NOW`, `OUT-OF-CYCLE`, `SCHEDULED`, `DEFER` |
| `reasoning` | array\<string\> | Ordered list of reasons the tier was assigned |

## CVSS object

| Field | Type | Description |
|-------|------|-------------|
| `score` | number | CVSS base score (0.0–10.0) |
| `vector` | string | CVSS vector string (omitted if unavailable) |
| `version` | string | CVSS version: `2.0`, `3.x`, `3.1` (omitted if unavailable) |
| `provenance` | string | Score source: `scanner`, `nvd`, `cna`, `ghsa` |

## KEV object

| Field | Type | Description |
|-------|------|-------------|
| `in_kev` | boolean | Whether the CVE is in the CISA Known Exploited Vulnerabilities catalog |
| `date_added` | string (YYYY-MM-DD) | Date added to KEV (omitted if `in_kev` is false) |
| `ransomware_campaign` | boolean | Whether KEV lists this as linked to ransomware campaigns (omitted if false) |

## EPSS object

| Field | Type | Description |
|-------|------|-------------|
| `score` | number | EPSS score: probability of exploitation in the next 30 days (0.0–1.0) |
| `percentile` | number | EPSS percentile (0.0–1.0) — fraction of CVEs with a lower score |

## SSVC object

| Field | Type | Description |
|-------|------|-------------|
| `exploitation` | string | `none`, `poc`, or `active` |
| `automatable` | string | `yes` or `no` |
| `technical_impact` | string | `partial` or `total` |

## Tier values

| Value | Meaning | Default SLA |
|-------|---------|-------------|
| `ACT NOW` | In CISA KEV (actively exploited in the wild) | 24 hours |
| `OUT-OF-CYCLE` | EPSS ≥ 8.8% or SSVC Exploitation=active | 7 days |
| `SCHEDULED` | EPSS ≥ 90th percentile or CVSS ≥ 7.0 | 30 days |
| `DEFER` | No escalation criteria met | 90 days |

## Example

```json
{
  "$schema": "https://github.com/sumeetghimire/culler/blob/main/docs/json-schema.md",
  "scan_time": "2024-01-15T12:00:00Z",
  "source": "grype",
  "summary": {
    "total": 42,
    "act_now": 2,
    "out_of_cycle": 5,
    "scheduled": 12,
    "defer": 23
  },
  "findings": [
    {
      "id": "CVE-2021-44228",
      "package": "log4j-core",
      "version": "2.14.1",
      "ecosystem": "maven",
      "fixed_in": ["2.15.0"],
      "source": "grype",
      "severity": "CRITICAL",
      "cvss": {
        "score": 10.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "version": "3.1",
        "provenance": "nvd"
      },
      "kev": {
        "in_kev": true,
        "date_added": "2021-12-10",
        "ransomware_campaign": true
      },
      "epss": {
        "score": 0.9999,
        "percentile": 0.99
      },
      "ssvc": {
        "exploitation": "active",
        "automatable": "yes",
        "technical_impact": "total"
      },
      "tier": "ACT NOW",
      "reasoning": ["in CISA KEV (added 2021-12-10) [ransomware-linked]"]
    }
  ],
  "warnings": []
}
```
