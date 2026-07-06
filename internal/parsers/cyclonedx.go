package parsers

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sumeetghimire/culler/internal/model"
)

// CycloneDX JSON schema (CycloneDX 1.4/1.5 with vulnerabilities)

type cdxReport struct {
	BOMFormat       string         `json:"bomFormat"`
	SpecVersion     string         `json:"specVersion"`
	Components      []cdxComponent `json:"components"`
	Vulnerabilities []cdxVuln      `json:"vulnerabilities"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	BOMRef  string `json:"bom-ref"`
	PURL    string `json:"purl"`
}

type cdxVuln struct {
	ID      string       `json:"id"`
	Source  cdxSource    `json:"source"`
	Ratings []cdxRating  `json:"ratings"`
	Affects []cdxAffects `json:"affects"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type cdxRating struct {
	Source   cdxSource `json:"source"`
	Score    float64   `json:"score"`
	Severity string    `json:"severity"`
	Method   string    `json:"method"`
	Vector   string    `json:"vector"`
}

type cdxAffects struct {
	Ref      string      `json:"ref"`
	Versions []cdxAffVer `json:"versions"`
}

type cdxAffVer struct {
	Version string `json:"version"`
	Status  string `json:"status"`
}

// ParseCycloneDX parses a CycloneDX JSON SBOM with embedded vulnerabilities.
func ParseCycloneDX(r io.Reader) ([]model.Finding, error) {
	var report cdxReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("cyclonedx: invalid JSON: %w", err)
	}

	// Build a ref → component lookup
	byRef := make(map[string]cdxComponent, len(report.Components))
	for _, c := range report.Components {
		if c.BOMRef != "" {
			byRef[c.BOMRef] = c
		}
	}

	var findings []model.Finding
	for _, v := range report.Vulnerabilities {
		cvss := cdxBestRating(v.Ratings)

		for _, affects := range v.Affects {
			comp, ok := byRef[affects.Ref]
			if !ok {
				// Ref not found — create a minimal finding with ref as package name
				comp = cdxComponent{Name: affects.Ref}
			}

			f := model.Finding{
				ID:        v.ID,
				Package:   comp.Name,
				Version:   comp.Version,
				Ecosystem: cdxEcosystem(comp.PURL),
				Source:    "cyclonedx",
				Severity:  cdxHighestSeverity(v.Ratings),
			}
			if cvss != nil {
				f.CVSS = cvss
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func cdxBestRating(ratings []cdxRating) *model.CVSSInfo {
	var best *cdxRating
	for i := range ratings {
		r := &ratings[i]
		if r.Score == 0 {
			continue
		}
		if best == nil || r.Score > best.Score {
			best = r
		}
	}
	if best == nil {
		return nil
	}
	prov := "scanner"
	switch strings.ToLower(best.Source.Name) {
	case "nvd":
		prov = "nvd"
	case "github":
		prov = "ghsa"
	}
	ver := "3.x"
	if strings.Contains(strings.ToUpper(best.Method), "CVSSV2") {
		ver = "2.0"
	}
	return &model.CVSSInfo{
		Score:      best.Score,
		Vector:     best.Vector,
		Version:    ver,
		Provenance: prov,
	}
}

func cdxHighestSeverity(ratings []cdxRating) string {
	order := map[string]int{
		"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0,
	}
	best := ""
	bestVal := -1
	for _, r := range ratings {
		sev := strings.ToLower(r.Severity)
		if v, ok := order[sev]; ok && v > bestVal {
			bestVal = v
			best = r.Severity
		}
	}
	return best
}

// cdxEcosystem infers ecosystem from a PURL string.
func cdxEcosystem(purl string) string {
	if purl == "" {
		return ""
	}
	// purl format: pkg:<type>/<namespace>/<name>@<version>
	purl = strings.TrimPrefix(purl, "pkg:")
	if idx := strings.Index(purl, "/"); idx > 0 {
		return purl[:idx]
	}
	return ""
}
