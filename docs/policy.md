# culler Policy File

Create `.culler.yaml` in your project root to customise culler's behaviour.

## Full Example

```yaml
# .culler.yaml

# Bump all findings one tier if the service is internet-facing
internet_facing: true

# Suppress specific CVEs with a mandatory reason
ignore:
  - id: CVE-2021-29425
    reason: "Path traversal only reachable via internal admin API; not exploitable"
  - id: CVE-2020-36518
    reason: "DoS only; service protected by rate limiting"
    expires: "2025-06-01"  # Re-evaluate after this date

# Override default thresholds
thresholds:
  epss_out_of_cycle: 0.05   # be more aggressive
  epss_percentile: 0.85
  cvss_scheduled: 6.5
```

## Fields

### `internet_facing`

When `true`, every finding is bumped one tier (DEFER→SCHEDULED, SCHEDULED→OUT-OF-CYCLE, etc.). Useful for public APIs or user-facing services.

### `ignore`

Each entry must have:
- `id` — CVE or GHSA ID to suppress
- `reason` — required explanation (for audit trail)
- `expires` — optional `YYYY-MM-DD` after which the ignore is automatically lifted

Expired ignores are silently re-activated; a warning is printed.

### `thresholds`

| Key | Default | Meaning |
|-----|---------|---------|
| `epss_out_of_cycle` | `0.088` | EPSS score threshold for OUT-OF-CYCLE |
| `epss_percentile` | `0.90` | EPSS percentile threshold for SCHEDULED |
| `cvss_scheduled` | `7.0` | CVSS base score threshold for SCHEDULED |

## Using a Custom Policy Path

```sh
culler scan report.json --policy /path/to/custom.yaml
```
