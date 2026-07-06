package decide

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sumeetghimire/culler/internal/model"
)

type noopEnrich struct{}

func (n noopEnrich) Enrich(_ *model.EnrichedFinding) {}

func finding(id string, cvssScore float64) model.Finding {
	f := model.Finding{ID: id, Package: "pkg", Version: "1.0"}
	if cvssScore > 0 {
		f.CVSS = &model.CVSSInfo{Score: cvssScore, Provenance: "nvd"}
	}
	return f
}

var cfg = DefaultConfig()

func TestTierActNow_KEV(t *testing.T) {
	ef := model.EnrichedFinding{
		Finding: finding("CVE-2021-44228", 10.0),
		KEV:     model.KEVInfo{InKEV: true, DateAdded: "2021-12-10", RansomwareCampaign: true},
	}
	assignTier(&ef, cfg)
	assert.Equal(t, model.TierActNow, ef.Tier)
	assert.Contains(t, ef.Reasoning[0], "CISA KEV")
	assert.Contains(t, ef.Reasoning[0], "ransomware-linked")
}

func TestTierOutOfCycle_EPSS(t *testing.T) {
	ef := model.EnrichedFinding{
		Finding: finding("CVE-2022-42889", 9.8),
		EPSS:    model.EPSSInfo{Score: 0.999, Percentile: 0.99},
	}
	assignTier(&ef, cfg)
	assert.Equal(t, model.TierOutOfCycle, ef.Tier)
	assert.Contains(t, ef.Reasoning[0], "EPSS")
}

func TestTierOutOfCycle_SSVC(t *testing.T) {
	ef := model.EnrichedFinding{
		Finding: finding("CVE-2022-0001", 5.0),
		SSVC:    &model.SSVCInfo{Exploitation: "active"},
	}
	assignTier(&ef, cfg)
	assert.Equal(t, model.TierOutOfCycle, ef.Tier)
	assert.Contains(t, ef.Reasoning[0], "SSVC")
}

func TestTierScheduled_EPSSPercentile(t *testing.T) {
	ef := model.EnrichedFinding{
		Finding: finding("CVE-2020-0001", 0),
		EPSS:    model.EPSSInfo{Score: 0.05, Percentile: 0.92},
	}
	assignTier(&ef, cfg)
	assert.Equal(t, model.TierScheduled, ef.Tier)
	assert.Contains(t, ef.Reasoning[0], "percentile")
}

func TestTierScheduled_CVSSHigh(t *testing.T) {
	ef := model.EnrichedFinding{
		Finding: finding("CVE-2022-9999", 7.5),
	}
	assignTier(&ef, cfg)
	assert.Equal(t, model.TierScheduled, ef.Tier)
	assert.Contains(t, ef.Reasoning[0], "CVSS")
}

func TestTierDefer(t *testing.T) {
	ef := model.EnrichedFinding{
		Finding: finding("CVE-2022-0002", 4.0),
		EPSS:    model.EPSSInfo{Score: 0.001, Percentile: 0.10},
	}
	assignTier(&ef, cfg)
	assert.Equal(t, model.TierDefer, ef.Tier)
}

func TestTierDefer_LowCVSS(t *testing.T) {
	ef := model.EnrichedFinding{
		Finding: finding("CVE-2022-0003", 3.5),
	}
	assignTier(&ef, cfg)
	assert.Equal(t, model.TierDefer, ef.Tier)
}

func TestKEVTakesPrecedenceOverEPSS(t *testing.T) {
	ef := model.EnrichedFinding{
		Finding: finding("CVE-2021-44228", 10.0),
		KEV:     model.KEVInfo{InKEV: true, DateAdded: "2021-12-10"},
		EPSS:    model.EPSSInfo{Score: 0.999, Percentile: 0.999},
	}
	assignTier(&ef, cfg)
	assert.Equal(t, model.TierActNow, ef.Tier)
	assert.Contains(t, ef.Reasoning[0], "KEV")
}

func TestRunEnrichesAll(t *testing.T) {
	findings := []model.Finding{
		finding("CVE-A", 9.0),
		finding("CVE-B", 2.0),
	}
	enriched := Run(findings, []Enrich{noopEnrich{}}, cfg)
	assert.Len(t, enriched, 2)
	assert.Equal(t, model.TierScheduled, enriched[0].Tier)
	assert.Equal(t, model.TierDefer, enriched[1].Tier)
}

func TestTierString(t *testing.T) {
	assert.Equal(t, "ACT NOW", model.TierActNow.String())
	assert.Equal(t, "OUT-OF-CYCLE", model.TierOutOfCycle.String())
	assert.Equal(t, "SCHEDULED", model.TierScheduled.String())
	assert.Equal(t, "DEFER", model.TierDefer.String())
}
