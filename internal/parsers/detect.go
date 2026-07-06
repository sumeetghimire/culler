package parsers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/sumeetghimire/culler/internal/model"
)

// Parse auto-detects the scanner format from the JSON shape and delegates.
func Parse(r io.Reader) ([]model.Finding, string, error) {
	// Buffer the input so we can peek at it then replay.
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, "", fmt.Errorf("reading input: %w", err)
	}

	format, err := detect(data)
	if err != nil {
		return nil, "", err
	}

	switch format {
	case "grype":
		findings, err := ParseGrype(bytes.NewReader(data))
		return findings, "grype", err
	case "trivy":
		findings, err := ParseTrivy(bytes.NewReader(data))
		return findings, "trivy", err
	case "osv":
		findings, err := ParseOSV(bytes.NewReader(data))
		return findings, "osv-scanner", err
	case "cyclonedx":
		findings, err := ParseCycloneDX(bytes.NewReader(data))
		return findings, "cyclonedx", err
	default:
		return nil, "", fmt.Errorf("unsupported format: %q", format)
	}
}

// detect inspects JSON keys to identify the scanner format.
func detect(data []byte) (string, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("input is not valid JSON: %w", err)
	}

	// Grype: has "matches" array and "descriptor.name" == "grype"
	if _, ok := probe["matches"]; ok {
		if descRaw, ok := probe["descriptor"]; ok {
			var desc struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(descRaw, &desc); err == nil && desc.Name == "grype" {
				return "grype", nil
			}
		}
		// "matches" without explicit descriptor — assume grype
		return "grype", nil
	}

	// Trivy: has "Results" array with "Vulnerabilities"
	if _, ok := probe["Results"]; ok {
		return "trivy", nil
	}

	// OSV-Scanner: has "results" with "packages"
	if _, ok := probe["results"]; ok {
		return "osv", nil
	}

	// CycloneDX: has "bomFormat" == "CycloneDX"
	if bomFmt, ok := probe["bomFormat"]; ok {
		var s string
		if json.Unmarshal(bomFmt, &s) == nil && s == "CycloneDX" {
			return "cyclonedx", nil
		}
	}

	return "", fmt.Errorf("could not detect scanner format — supported: grype, trivy, osv-scanner, cyclonedx")
}
