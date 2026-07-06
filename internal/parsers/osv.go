package parsers

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sumeetghimire/culler/internal/model"
)

// OSV-Scanner JSON schema (osv-scanner --format json)

type osvReport struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvPackage struct {
	Package         osvPkg     `json:"package"`
	Groups          []osvGroup `json:"groups"`
	Vulnerabilities []osvVuln  `json:"vulnerabilities"`
}

type osvPkg struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvGroup struct {
	IDs []string `json:"ids"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Aliases  []string      `json:"aliases"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package osvPkg     `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

// ParseOSV parses OSV-Scanner JSON output into normalized Findings.
func ParseOSV(r io.Reader) ([]model.Finding, error) {
	var report osvReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("osv-scanner: invalid JSON: %w", err)
	}

	var findings []model.Finding
	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				// Prefer CVE alias over GHSA/OSV ID
				id := vuln.ID
				for _, alias := range vuln.Aliases {
					if len(alias) > 4 && alias[:4] == "CVE-" {
						id = alias
						break
					}
				}

				f := model.Finding{
					ID:        id,
					Package:   pkg.Package.Name,
					Version:   pkg.Package.Version,
					Ecosystem: pkg.Package.Ecosystem,
					Source:    "osv",
					FixedIn:   osvFixVersions(vuln.Affected, pkg.Package.Name),
				}

				// Parse CVSS from severity field if present
				if cvss := osvCVSS(vuln.Severity); cvss != nil {
					f.CVSS = cvss
				}

				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}

func osvFixVersions(affected []osvAffected, pkgName string) []string {
	var fixes []string
	for _, a := range affected {
		for _, rng := range a.Ranges {
			for _, ev := range rng.Events {
				if ev.Fixed != "" {
					fixes = append(fixes, ev.Fixed)
				}
			}
		}
	}
	return fixes
}

// osvCVSS extracts a CVSS score from the OSV severity array.
// OSV uses CVSS_V3 type with a vector string like "CVSS:3.1/AV:N/..."
func osvCVSS(severities []osvSeverity) *model.CVSSInfo {
	for _, s := range severities {
		if s.Type == "CVSS_V3" && s.Score != "" {
			score := parseCVSSVectorScore(s.Score)
			if score > 0 {
				return &model.CVSSInfo{
					Score:      score,
					Vector:     s.Score,
					Version:    "3.x",
					Provenance: "ghsa",
				}
			}
		}
	}
	return nil
}

// parseCVSSVectorScore extracts the base score from a CVSS vector string.
// OSV stores the full vector, not just the score, so we need to compute it.
// As a simple heuristic, parse AV/AC/PR/UI/S/C/I/A from the vector.
// For a complete implementation this would use a CVSS library, but for now
// we skip scoring and return 0 (the enricher will use EPSS/KEV instead).
func parseCVSSVectorScore(vector string) float64 {
	// OSV severity Score field contains just the CVSS vector string.
	// We'd need a CVSS calculator to convert vector → score.
	// Return 0 to indicate "no score available from this source";
	// the decision engine falls back to EPSS/KEV which is sufficient.
	_ = vector
	return 0
}
