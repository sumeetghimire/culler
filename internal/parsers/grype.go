package parsers

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sumeetghimire/culler/internal/model"
)

// grype JSON schema types

type grypeReport struct {
	Matches    []grypeMatch `json:"matches"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
}

type grypeMatch struct {
	Vulnerability grypeVulnerability `json:"vulnerability"`
	Artifact      grypeArtifact      `json:"artifact"`
}

type grypeVulnerability struct {
	ID       string      `json:"id"`
	Severity string      `json:"severity"`
	CVSS     []grypeCVSS `json:"cvss"`
	Fix      struct {
		Versions []string `json:"versions"`
		State    string   `json:"state"`
	} `json:"fix"`
}

type grypeCVSS struct {
	Version string `json:"version"`
	Vector  string `json:"vector"`
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
	Source string `json:"source"`
}

type grypeArtifact struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	Language string `json:"language"`
}

// ParseGrype parses Grype JSON output into a slice of normalized Findings.
func ParseGrype(r io.Reader) ([]model.Finding, error) {
	var report grypeReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("grype: invalid JSON: %w", err)
	}

	findings := make([]model.Finding, 0, len(report.Matches))
	for _, m := range report.Matches {
		f := model.Finding{
			ID:        m.Vulnerability.ID,
			Package:   m.Artifact.Name,
			Version:   m.Artifact.Version,
			Ecosystem: ecosystem(m.Artifact.Language, m.Artifact.Type),
			FixedIn:   m.Vulnerability.Fix.Versions,
			Source:    "grype",
			Severity:  m.Vulnerability.Severity,
		}

		// Pick the best CVSS score: prefer v3.x over v2.
		if cvss := bestCVSS(m.Vulnerability.CVSS); cvss != nil {
			f.CVSS = cvss
		}

		findings = append(findings, f)
	}
	return findings, nil
}

// bestCVSS picks the highest-version CVSS entry and returns a CVSSInfo.
func bestCVSS(scores []grypeCVSS) *model.CVSSInfo {
	var best *grypeCVSS
	for i := range scores {
		s := &scores[i]
		if best == nil {
			best = s
			continue
		}
		// Prefer v3.x over v2
		if strings.HasPrefix(s.Version, "3") && !strings.HasPrefix(best.Version, "3") {
			best = s
		}
	}
	if best == nil || best.Metrics.BaseScore == 0 {
		return nil
	}
	prov := "scanner"
	if strings.Contains(best.Source, "nvd") {
		prov = "nvd"
	} else if best.Source != "" {
		prov = "cna"
	}
	return &model.CVSSInfo{
		Score:      best.Metrics.BaseScore,
		Vector:     best.Vector,
		Version:    best.Version,
		Provenance: prov,
	}
}

// ecosystem maps Grype language/type to a normalized ecosystem string.
func ecosystem(language, typ string) string {
	if language != "" {
		switch strings.ToLower(language) {
		case "java":
			return "maven"
		case "python":
			return "pypi"
		case "javascript", "typescript":
			return "npm"
		case "go":
			return "go"
		case "ruby":
			return "gem"
		case "rust":
			return "cargo"
		case "php":
			return "packagist"
		}
		return strings.ToLower(language)
	}
	switch strings.ToLower(typ) {
	case "deb":
		return "deb"
	case "rpm":
		return "rpm"
	case "apk":
		return "apk"
	}
	return typ
}
