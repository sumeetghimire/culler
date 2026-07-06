package model

import "time"

// Tier represents the remediation priority assigned by the decision engine.
type Tier int

const (
	TierActNow     Tier = iota // In CISA KEV
	TierOutOfCycle             // EPSS >= threshold or SSVC Exploitation=active
	TierScheduled              // EPSS >= 90th pct or (CVSS >= 7.0 and Automatable)
	TierDefer                  // No escalation criteria met
)

func (t Tier) String() string {
	switch t {
	case TierActNow:
		return "ACT NOW"
	case TierOutOfCycle:
		return "OUT-OF-CYCLE"
	case TierScheduled:
		return "SCHEDULED"
	case TierDefer:
		return "DEFER"
	default:
		return "UNKNOWN"
	}
}

func (t Tier) Label() string {
	switch t {
	case TierActNow:
		return "NOW"
	case TierOutOfCycle:
		return "OOC"
	case TierScheduled:
		return "SCHED"
	case TierDefer:
		return "DEFER"
	default:
		return "???"
	}
}

// CVSSInfo holds a CVSS score with provenance tracking.
type CVSSInfo struct {
	Score      float64
	Vector     string
	Version    string
	Provenance string // "scanner", "nvd", "cna", "ghsa"
}

// Finding is a normalized vulnerability finding from any scanner.
type Finding struct {
	ID        string // CVE-YYYY-NNNNN or GHSA-xxxx-xxxx-xxxx
	Package   string
	Version   string
	Ecosystem string
	FixedIn   []string
	Source    string // grype, trivy, osv, cyclonedx
	CVSS      *CVSSInfo
	Severity  string // raw severity string from scanner
}

// KEVInfo holds CISA Known Exploited Vulnerability data.
type KEVInfo struct {
	InKEV              bool
	DateAdded          string
	RansomwareCampaign bool
}

// EPSSInfo holds FIRST EPSS score data.
type EPSSInfo struct {
	Score      float64 // 0.0–1.0
	Percentile float64 // 0.0–1.0
}

// SSVCInfo holds CISA Vulnrichment SSVC decision points.
type SSVCInfo struct {
	Exploitation    string // "none", "poc", "active"
	Automatable     string // "yes", "no"
	TechnicalImpact string // "partial", "total"
}

// EnrichedFinding extends Finding with threat-intel data and the tier decision.
type EnrichedFinding struct {
	Finding
	KEV       KEVInfo
	EPSS      EPSSInfo
	SSVC      *SSVCInfo
	Tier      Tier
	Reasoning []string
}

// ScanResult is the complete output of a scan run.
type ScanResult struct {
	Findings []EnrichedFinding
	ScanTime time.Time
	Source   string
	Warnings []string
}
