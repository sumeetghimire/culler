package decide

import (
	"fmt"

	"github.com/sumeetghimire/culler/internal/model"
)

// Config holds tunable thresholds for the decision engine.
type Config struct {
	EPSSThreshold  float64 // default 0.088 — OUT-OF-CYCLE threshold
	EPSSPercentile float64 // default 0.90  — SCHEDULED threshold
	CVSSThreshold  float64 // default 7.0   — SCHEDULED threshold
}

// DefaultConfig returns the default decision thresholds from the spec.
func DefaultConfig() Config {
	return Config{
		EPSSThreshold:  0.088,
		EPSSPercentile: 0.90,
		CVSSThreshold:  7.0,
	}
}

// Enrich is the interface any enricher must satisfy.
type Enrich interface {
	Enrich(ef *model.EnrichedFinding)
}

// Run enriches each finding and assigns a remediation tier.
func Run(findings []model.Finding, enrichers []Enrich, cfg Config) []model.EnrichedFinding {
	results := make([]model.EnrichedFinding, len(findings))
	for i, f := range findings {
		ef := model.EnrichedFinding{Finding: f}
		for _, e := range enrichers {
			e.Enrich(&ef)
		}
		assignTier(&ef, cfg)
		results[i] = ef
	}
	return results
}

func assignTier(ef *model.EnrichedFinding, cfg Config) {
	// Rule 1 — In CISA KEV → ACT NOW
	if ef.KEV.InKEV {
		ef.Tier = model.TierActNow
		reason := fmt.Sprintf("in CISA KEV (added %s)", ef.KEV.DateAdded)
		if ef.KEV.RansomwareCampaign {
			reason += " [ransomware-linked]"
		}
		ef.Reasoning = append(ef.Reasoning, reason)
		return
	}

	// Rule 2 — EPSS ≥ threshold or SSVC Exploitation=active → OUT-OF-CYCLE
	if ef.EPSS.Score >= cfg.EPSSThreshold && ef.EPSS.Score > 0 {
		ef.Tier = model.TierOutOfCycle
		ef.Reasoning = append(ef.Reasoning,
			fmt.Sprintf("EPSS %.4f ≥ %.3f threshold", ef.EPSS.Score, cfg.EPSSThreshold))
		return
	}
	if ef.SSVC != nil && ef.SSVC.Exploitation == "active" {
		ef.Tier = model.TierOutOfCycle
		ef.Reasoning = append(ef.Reasoning, "SSVC Exploitation=active")
		return
	}

	// Rule 3 — EPSS ≥ 90th percentile or (CVSS ≥ 7.0 and Automatable) → SCHEDULED
	if ef.EPSS.Percentile >= cfg.EPSSPercentile && ef.EPSS.Percentile > 0 {
		ef.Tier = model.TierScheduled
		ef.Reasoning = append(ef.Reasoning,
			fmt.Sprintf("EPSS percentile %.1f%% ≥ %.0f%%", ef.EPSS.Percentile*100, cfg.EPSSPercentile*100))
		return
	}
	if ef.Finding.CVSS != nil && ef.Finding.CVSS.Score >= cfg.CVSSThreshold {
		if ef.SSVC != nil && ef.SSVC.Automatable == "yes" {
			ef.Tier = model.TierScheduled
			ef.Reasoning = append(ef.Reasoning,
				fmt.Sprintf("CVSS %.1f ≥ %.1f and SSVC Automatable=yes", ef.Finding.CVSS.Score, cfg.CVSSThreshold))
			return
		}
		// High CVSS without SSVC data — still schedule
		ef.Tier = model.TierScheduled
		ef.Reasoning = append(ef.Reasoning,
			fmt.Sprintf("CVSS %.1f ≥ %.1f", ef.Finding.CVSS.Score, cfg.CVSSThreshold))
		return
	}

	// Rule 4 — Defer
	ef.Tier = model.TierDefer
	ef.Reasoning = append(ef.Reasoning, "no escalation criteria met")
}
