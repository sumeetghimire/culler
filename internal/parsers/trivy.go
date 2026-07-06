package parsers

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sumeetghimire/culler/internal/model"
)

// Trivy JSON schema (trivy fs/image --format json)

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string             `json:"Target"`
	Type            string             `json:"Type"`
	Vulnerabilities []trivyVuln        `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string     `json:"VulnerabilityID"`
	PkgName          string     `json:"PkgName"`
	InstalledVersion string     `json:"InstalledVersion"`
	FixedVersion     string     `json:"FixedVersion"`
	Severity         string     `json:"Severity"`
	CVSS             trivyCVSS  `json:"CVSS"`
}

type trivyCVSS struct {
	NVD  *trivyCVSSEntry `json:"nvd"`
	RedHat *trivyCVSSEntry `json:"redhat"`
}

type trivyCVSSEntry struct {
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector"`
	V2Score  float64 `json:"V2Score"`
	V2Vector string  `json:"V2Vector"`
}

// ParseTrivy parses Trivy JSON output into normalized Findings.
func ParseTrivy(r io.Reader) ([]model.Finding, error) {
	var report trivyReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("trivy: invalid JSON: %w", err)
	}

	var findings []model.Finding
	for _, result := range report.Results {
		eco := trivyEcosystem(result.Type)
		for _, v := range result.Vulnerabilities {
			f := model.Finding{
				ID:        v.VulnerabilityID,
				Package:   v.PkgName,
				Version:   v.InstalledVersion,
				Ecosystem: eco,
				Source:    "trivy",
				Severity:  v.Severity,
			}
			if v.FixedVersion != "" {
				f.FixedIn = []string{v.FixedVersion}
			}
			if cvss := trivyBestCVSS(v.CVSS); cvss != nil {
				f.CVSS = cvss
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func trivyBestCVSS(c trivyCVSS) *model.CVSSInfo {
	// Prefer NVD v3 > RedHat v3 > NVD v2
	if c.NVD != nil && c.NVD.V3Score > 0 {
		return &model.CVSSInfo{
			Score:      c.NVD.V3Score,
			Vector:     c.NVD.V3Vector,
			Version:    "3.x",
			Provenance: "nvd",
		}
	}
	if c.RedHat != nil && c.RedHat.V3Score > 0 {
		return &model.CVSSInfo{
			Score:      c.RedHat.V3Score,
			Vector:     c.RedHat.V3Vector,
			Version:    "3.x",
			Provenance: "cna",
		}
	}
	if c.NVD != nil && c.NVD.V2Score > 0 {
		return &model.CVSSInfo{
			Score:      c.NVD.V2Score,
			Vector:     c.NVD.V2Vector,
			Version:    "2.0",
			Provenance: "nvd",
		}
	}
	return nil
}

func trivyEcosystem(typ string) string {
	switch strings.ToLower(typ) {
	case "jar", "pom", "gradle":
		return "maven"
	case "gobinary", "gomodule":
		return "go"
	case "npm", "node-pkg":
		return "npm"
	case "pip", "pipenv", "poetry":
		return "pypi"
	case "gemspec", "bundler":
		return "gem"
	case "cargo":
		return "cargo"
	case "nuget":
		return "nuget"
	case "ubuntu", "debian":
		return "deb"
	case "centos", "rhel", "fedora", "rocky", "alma":
		return "rpm"
	case "alpine":
		return "apk"
	}
	return strings.ToLower(typ)
}
