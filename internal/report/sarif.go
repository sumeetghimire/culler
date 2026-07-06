package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sumeetghimire/culler/internal/model"
)

// SARIF 2.1.0 output — valid for GitHub Code Scanning upload.

type sarifLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"` // error, warning, note
	Message   sarifMessage   `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// WriteSARIF writes a SARIF 2.1.0 report to w.
func WriteSARIF(w io.Writer, result *model.ScanResult) error {
	// Build rules (one per unique CVE)
	ruleMap := make(map[string]bool)
	var rules []sarifRule
	for _, f := range result.Findings {
		if ruleMap[f.ID] {
			continue
		}
		ruleMap[f.ID] = true
		desc := f.ID
		if f.Severity != "" {
			desc += " (" + f.Severity + ")"
		}
		rules = append(rules, sarifRule{
			ID:   f.ID,
			Name: strings.ReplaceAll(f.ID, "-", ""),
			ShortDescription: sarifMessage{Text: desc},
			Properties: map[string]string{
				"tier": f.Tier.String(),
			},
		})
	}

	// Build results
	var results []sarifResult
	for _, f := range result.Findings {
		level := tierToSARIFLevel(f.Tier)
		msg := fmt.Sprintf("%s in %s %s — tier: %s. %s",
			f.ID, f.Package, f.Version, f.Tier.String(),
			strings.Join(f.Reasoning, "; "))

		props := map[string]interface{}{
			"tier":       f.Tier.String(),
			"epss_score": f.EPSS.Score,
			"in_kev":     f.KEV.InKEV,
		}
		if f.Finding.CVSS != nil {
			props["cvss_score"] = f.Finding.CVSS.Score
			props["cvss_provenance"] = f.Finding.CVSS.Provenance
		}

		r := sarifResult{
			RuleID:     f.ID,
			Level:      level,
			Message:    sarifMessage{Text: msg},
			Properties: props,
		}
		// Use package as a pseudo-location
		r.Locations = []sarifLocation{{
			PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: f.Package},
			},
		}}
		results = append(results, r)
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "culler",
						Version:        "dev",
						InformationURI: "https://github.com/sumeetghimire/culler",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("writing SARIF report: %w", err)
	}
	return nil
}

func tierToSARIFLevel(t model.Tier) string {
	switch t {
	case model.TierActNow:
		return "error"
	case model.TierOutOfCycle:
		return "error"
	case model.TierScheduled:
		return "warning"
	case model.TierDefer:
		return "note"
	}
	return "note"
}
