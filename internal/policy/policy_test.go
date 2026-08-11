package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sumeetghimire/culler/internal/model"
)

func TestLoad_Missing(t *testing.T) {
	cfg, err := Load("/nonexistent/.culler.yaml")
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Empty(t, cfg.Ignore)
}

func TestLoad_ValidFile(t *testing.T) {
	yaml := `
internet_facing: true
ignore:
  - id: CVE-2021-99999
    reason: "not reachable"
    expires: "2099-01-01"
thresholds:
  epss_out_of_cycle: 0.05
  cvss_scheduled: 8.0
`
	f := writeTempYAML(t, yaml)
	cfg, err := Load(f)
	require.NoError(t, err)
	assert.True(t, cfg.InternetFacing)
	require.Len(t, cfg.Ignore, 1)
	assert.Equal(t, "CVE-2021-99999", cfg.Ignore[0].ID)
	assert.Equal(t, "not reachable", cfg.Ignore[0].Reason)
	require.NotNil(t, cfg.Thresholds)
	assert.Equal(t, 0.05, cfg.Thresholds.EPSSOutOfCycle)
	assert.Equal(t, 8.0, cfg.Thresholds.CVSSScheduled)
}

func TestLoad_InvalidYAML(t *testing.T) {
	// A tab at the start of a YAML block is a parse error in yaml.v3
	f := writeTempYAML(t, "ignore:\n\t- id: bad")
	_, err := Load(f)
	assert.Error(t, err)
}

func TestApply_IgnoreActive(t *testing.T) {
	findings := []model.EnrichedFinding{
		{Finding: model.Finding{ID: "CVE-2021-00001"}, Tier: model.TierActNow},
		{Finding: model.Finding{ID: "CVE-2021-00002"}, Tier: model.TierScheduled},
	}
	cfg := &Config{
		Ignore: []IgnoreEntry{
			{ID: "CVE-2021-00001", Reason: "risk accepted"},
		},
	}
	result, suppressed := Apply(findings, cfg)
	assert.Len(t, result, 1)
	assert.Equal(t, "CVE-2021-00002", result[0].ID)
	require.Len(t, suppressed, 1)
	assert.Contains(t, suppressed[0], "CVE-2021-00001")
	assert.Contains(t, suppressed[0], "risk accepted")
}

func TestApply_IgnoreExpired(t *testing.T) {
	findings := []model.EnrichedFinding{
		{Finding: model.Finding{ID: "CVE-2021-00001"}, Tier: model.TierActNow},
	}
	cfg := &Config{
		Ignore: []IgnoreEntry{
			{ID: "CVE-2021-00001", Reason: "old waiver", Expires: "2020-01-01"},
		},
	}
	result, suppressed := Apply(findings, cfg)
	// Expired — finding should NOT be suppressed
	assert.Len(t, result, 1)
	assert.Empty(t, suppressed)
}

func TestApply_InternetFacingBump(t *testing.T) {
	findings := []model.EnrichedFinding{
		{Finding: model.Finding{ID: "CVE-A"}, Tier: model.TierScheduled},
		{Finding: model.Finding{ID: "CVE-B"}, Tier: model.TierDefer},
		{Finding: model.Finding{ID: "CVE-C"}, Tier: model.TierActNow}, // already top tier, no change
	}
	cfg := &Config{InternetFacing: true}
	result, _ := Apply(findings, cfg)
	assert.Equal(t, model.TierOutOfCycle, result[0].Tier) // Scheduled → OOC
	assert.Equal(t, model.TierScheduled, result[1].Tier)  // Defer → Scheduled
	assert.Equal(t, model.TierActNow, result[2].Tier)     // ActNow stays
}

func TestApply_NilConfig(t *testing.T) {
	findings := []model.EnrichedFinding{
		{Finding: model.Finding{ID: "CVE-X"}, Tier: model.TierDefer},
	}
	result, suppressed := Apply(findings, nil)
	assert.Equal(t, findings, result)
	assert.Empty(t, suppressed)
}

func TestIsExpired(t *testing.T) {
	assert.False(t, isExpired(""))
	assert.True(t, isExpired("2000-01-01"))
	assert.False(t, isExpired(time.Now().AddDate(1, 0, 0).Format("2006-01-02")))
	assert.False(t, isExpired("not-a-date"))
}

func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".culler.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}
