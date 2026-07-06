package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sumeetghimire/culler/internal/model"
)

// JSONFinding is the documented JSON output schema for a single finding.
type JSONFinding struct {
	ID        string   `json:"id"`
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	FixedIn   []string `json:"fixed_in"`
	Source    string   `json:"source"`
	Severity  string   `json:"severity,omitempty"`
	CVSS      *JSONCVSSInfo `json:"cvss,omitempty"`
	KEV       JSONKEVInfo   `json:"kev"`
	EPSS      JSONEPSSInfo  `json:"epss"`
	SSVC      *model.SSVCInfo `json:"ssvc,omitempty"`
	Tier      string   `json:"tier"`
	Reasoning []string `json:"reasoning"`
}

type JSONCVSSInfo struct {
	Score      float64 `json:"score"`
	Vector     string  `json:"vector,omitempty"`
	Version    string  `json:"version,omitempty"`
	Provenance string  `json:"provenance"`
}

type JSONKEVInfo struct {
	InKEV              bool   `json:"in_kev"`
	DateAdded          string `json:"date_added,omitempty"`
	RansomwareCampaign bool   `json:"ransomware_campaign,omitempty"`
}

type JSONEPSSInfo struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

// JSONReport is the top-level JSON output document.
type JSONReport struct {
	Schema   string        `json:"$schema"`
	ScanTime string        `json:"scan_time"`
	Source   string        `json:"source"`
	Summary  JSONSummary   `json:"summary"`
	Findings []JSONFinding `json:"findings"`
	Warnings []string      `json:"warnings,omitempty"`
}

type JSONSummary struct {
	Total      int `json:"total"`
	ActNow     int `json:"act_now"`
	OutOfCycle int `json:"out_of_cycle"`
	Scheduled  int `json:"scheduled"`
	Defer      int `json:"defer"`
}

// WriteJSON writes a JSON report to w.
func WriteJSON(w io.Writer, result *model.ScanResult) error {
	counts := tierCounts(result.Findings)
	report := JSONReport{
		Schema:   "https://github.com/sumeetghimire/culler/blob/main/docs/json-schema.md",
		ScanTime: result.ScanTime.UTC().Format("2006-01-02T15:04:05Z"),
		Source:   result.Source,
		Summary: JSONSummary{
			Total:      len(result.Findings),
			ActNow:     counts[model.TierActNow],
			OutOfCycle: counts[model.TierOutOfCycle],
			Scheduled:  counts[model.TierScheduled],
			Defer:      counts[model.TierDefer],
		},
		Warnings: result.Warnings,
	}

	for _, f := range result.Findings {
		jf := JSONFinding{
			ID:        f.ID,
			Package:   f.Package,
			Version:   f.Version,
			Ecosystem: f.Ecosystem,
			FixedIn:   f.FixedIn,
			Source:    f.Source,
			Severity:  f.Severity,
			KEV: JSONKEVInfo{
				InKEV:              f.KEV.InKEV,
				DateAdded:          f.KEV.DateAdded,
				RansomwareCampaign: f.KEV.RansomwareCampaign,
			},
			EPSS: JSONEPSSInfo{
				Score:      f.EPSS.Score,
				Percentile: f.EPSS.Percentile,
			},
			SSVC:      f.SSVC,
			Tier:      f.Tier.String(),
			Reasoning: f.Reasoning,
		}
		if f.Finding.CVSS != nil {
			jf.CVSS = &JSONCVSSInfo{
				Score:      f.Finding.CVSS.Score,
				Vector:     f.Finding.CVSS.Vector,
				Version:    f.Finding.CVSS.Version,
				Provenance: f.Finding.CVSS.Provenance,
			}
		}
		report.Findings = append(report.Findings, jf)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("writing JSON report: %w", err)
	}
	return nil
}
