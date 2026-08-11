package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sumeetghimire/culler/internal/model"
)

func sampleResult() *model.ScanResult {
	return &model.ScanResult{
		Source:   "grype",
		ScanTime: time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
		Findings: []model.EnrichedFinding{
			{
				Finding: model.Finding{
					ID:        "CVE-2021-44228",
					Package:   "log4j-core",
					Version:   "2.14.1",
					Ecosystem: "java",
					FixedIn:   []string{"2.15.0"},
					Source:    "grype",
					CVSS:      &model.CVSSInfo{Score: 10.0, Vector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Version: "3.1", Provenance: "nvd"},
				},
				KEV:       model.KEVInfo{InKEV: true, DateAdded: "2021-12-10", RansomwareCampaign: true},
				EPSS:      model.EPSSInfo{Score: 0.9999, Percentile: 0.99},
				Tier:      model.TierActNow,
				Reasoning: []string{"in CISA KEV (added 2021-12-10) [ransomware-linked]"},
			},
			{
				Finding: model.Finding{
					ID:        "CVE-2022-42889",
					Package:   "commons-text",
					Version:   "1.9",
					Ecosystem: "java",
					FixedIn:   []string{"1.10.0"},
					Source:    "grype",
				},
				EPSS:      model.EPSSInfo{Score: 0.9993, Percentile: 0.97},
				Tier:      model.TierOutOfCycle,
				Reasoning: []string{"EPSS 0.9993 ≥ 0.088 threshold"},
			},
			{
				Finding: model.Finding{
					ID:      "CVE-2022-00001",
					Package: "somelib",
					Version: "1.0.0",
					Source:  "grype",
				},
				Tier:      model.TierDefer,
				Reasoning: []string{"no escalation criteria met"},
			},
		},
	}
}

// ── Terminal ──────────────────────────────────────────────────────────────────

func TestTerminal_Print_Summary(t *testing.T) {
	var buf bytes.Buffer
	r := &Terminal{out: &buf, color: false}
	r.Print(sampleResult(), false)
	out := buf.String()
	assert.Contains(t, out, "3 findings")
	assert.Contains(t, out, "1 ACT NOW")
	assert.Contains(t, out, "1 OUT-OF-CYCLE")
}

func TestTerminal_Print_ShowAll(t *testing.T) {
	var buf bytes.Buffer
	r := &Terminal{out: &buf, color: false}
	r.Print(sampleResult(), true)
	out := buf.String()
	assert.Contains(t, out, "CVE-2021-44228")
	assert.Contains(t, out, "CVE-2022-42889")
	assert.Contains(t, out, "CVE-2022-00001")
}

func TestTerminal_Print_HideDefer(t *testing.T) {
	var buf bytes.Buffer
	r := &Terminal{out: &buf, color: false}
	r.Print(sampleResult(), false)
	out := buf.String()
	assert.NotContains(t, out, "CVE-2022-00001")
	assert.Contains(t, out, "hidden")
}

func TestTerminal_Print_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &Terminal{out: &buf, color: false}
	r.Print(&model.ScanResult{}, false)
	// Should not panic; summary line should say 0 findings
	assert.Contains(t, buf.String(), "0 findings")
}

func TestTerminal_Print_KEVLabel(t *testing.T) {
	var buf bytes.Buffer
	r := &Terminal{out: &buf, color: false}
	r.Print(sampleResult(), false)
	assert.Contains(t, buf.String(), "KEV✓")
}

// ── JSON ──────────────────────────────────────────────────────────────────────

func TestWriteJSON_ValidOutput(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, sampleResult())
	require.NoError(t, err)

	var report JSONReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report))
	assert.Equal(t, "grype", report.Source)
	assert.Equal(t, 3, report.Summary.Total)
	assert.Equal(t, 1, report.Summary.ActNow)
	assert.Equal(t, 1, report.Summary.OutOfCycle)
	assert.Equal(t, 1, report.Summary.Defer)
	require.Len(t, report.Findings, 3)
	assert.Equal(t, "CVE-2021-44228", report.Findings[0].ID)
	assert.Equal(t, "ACT NOW", report.Findings[0].Tier)
	require.NotNil(t, report.Findings[0].CVSS)
	assert.Equal(t, 10.0, report.Findings[0].CVSS.Score)
	assert.True(t, report.Findings[0].KEV.InKEV)
	assert.True(t, report.Findings[0].KEV.RansomwareCampaign)
}

func TestWriteJSON_NoCVSS(t *testing.T) {
	var buf bytes.Buffer
	result := &model.ScanResult{
		Findings: []model.EnrichedFinding{
			{Finding: model.Finding{ID: "CVE-X", Package: "pkg"}, Tier: model.TierDefer},
		},
	}
	require.NoError(t, WriteJSON(&buf, result))
	var report JSONReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report))
	assert.Nil(t, report.Findings[0].CVSS)
}

// ── SARIF ─────────────────────────────────────────────────────────────────────

func TestWriteSARIF_ValidOutput(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSARIF(&buf, sampleResult())
	require.NoError(t, err)

	var log sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))
	assert.Equal(t, "2.1.0", log.Version)
	require.Len(t, log.Runs, 1)
	run := log.Runs[0]
	assert.Equal(t, "culler", run.Tool.Driver.Name)
	assert.Len(t, run.Tool.Driver.Rules, 3)
	assert.Len(t, run.Results, 3)
}

func TestWriteSARIF_TierToLevel(t *testing.T) {
	assert.Equal(t, "error", tierToSARIFLevel(model.TierActNow))
	assert.Equal(t, "error", tierToSARIFLevel(model.TierOutOfCycle))
	assert.Equal(t, "warning", tierToSARIFLevel(model.TierScheduled))
	assert.Equal(t, "note", tierToSARIFLevel(model.TierDefer))
}

func TestWriteSARIF_DeduplicatesRules(t *testing.T) {
	result := &model.ScanResult{
		Findings: []model.EnrichedFinding{
			{Finding: model.Finding{ID: "CVE-X"}, Tier: model.TierDefer},
			{Finding: model.Finding{ID: "CVE-X"}, Tier: model.TierDefer}, // duplicate
		},
	}
	var buf bytes.Buffer
	require.NoError(t, WriteSARIF(&buf, result))
	var log sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))
	assert.Len(t, log.Runs[0].Tool.Driver.Rules, 1)
	assert.Len(t, log.Runs[0].Results, 2)
}

// ── Markdown ──────────────────────────────────────────────────────────────────

func TestWriteMarkdown_ContainsSections(t *testing.T) {
	var buf bytes.Buffer
	err := WriteMarkdown(&buf, sampleResult(), false)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "## culler Vulnerability Triage Report")
	assert.Contains(t, out, "ACT NOW")
	assert.Contains(t, out, "CVE-2021-44228")
	assert.Contains(t, out, "CVE-2022-42889")
	// Defer not shown without --all
	assert.NotContains(t, out, "CVE-2022-00001")
}

func TestWriteMarkdown_ShowAll(t *testing.T) {
	var buf bytes.Buffer
	err := WriteMarkdown(&buf, sampleResult(), true)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "CVE-2022-00001")
}

func TestWriteMarkdown_NoHighPriority(t *testing.T) {
	result := &model.ScanResult{
		Findings: []model.EnrichedFinding{
			{Finding: model.Finding{ID: "CVE-X"}, Tier: model.TierDefer},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, WriteMarkdown(&buf, result, false))
	assert.Contains(t, buf.String(), "No ACT NOW or OUT-OF-CYCLE")
}

func TestWriteMarkdown_RansomwareFlag(t *testing.T) {
	result := &model.ScanResult{
		Findings: []model.EnrichedFinding{
			{
				Finding: model.Finding{ID: "CVE-R"},
				KEV:     model.KEVInfo{InKEV: true, RansomwareCampaign: true},
				Tier:    model.TierActNow,
			},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, WriteMarkdown(&buf, result, false))
	assert.Contains(t, buf.String(), "ransomware")
}

// ── tierCounts helper ─────────────────────────────────────────────────────────

func TestTierCounts(t *testing.T) {
	counts := tierCounts(sampleResult().Findings)
	assert.Equal(t, 1, counts[model.TierActNow])
	assert.Equal(t, 1, counts[model.TierOutOfCycle])
	assert.Equal(t, 0, counts[model.TierScheduled])
	assert.Equal(t, 1, counts[model.TierDefer])
}

func TestTierEmoji(t *testing.T) {
	assert.Equal(t, "🔴", tierEmoji(model.TierActNow))
	assert.Equal(t, "🟠", tierEmoji(model.TierOutOfCycle))
	assert.Equal(t, "🟡", tierEmoji(model.TierScheduled))
	assert.Equal(t, "⚪", tierEmoji(model.TierDefer))
}

// ── Footnote / disclaimer ─────────────────────────────────────────────────────

func TestTerminal_Footnote(t *testing.T) {
	var buf bytes.Buffer
	r := &Terminal{out: &buf, color: false}
	r.Print(sampleResult(), false)
	assert.Contains(t, buf.String(), "EPSS scores lag")
}

func TestMarkdown_Disclaimer(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteMarkdown(&buf, sampleResult(), false))
	assert.True(t, strings.Contains(buf.String(), "decision support"))
}
