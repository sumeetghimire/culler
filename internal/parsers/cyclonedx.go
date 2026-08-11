package parsers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sumeetghimire/culler/internal/model"
)

// CycloneDX JSON schema (CycloneDX 1.4/1.5 with or without vulnerabilities)

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

// osvHTTPClient and osvQueryBatchURL can be overridden in tests.
var (
	osvHTTPClient    = &http.Client{Timeout: 30 * time.Second}
	osvQueryBatchURL = "https://api.osv.dev/v1/querybatch"
)

// OSV batch API types (prefixed cdxOSV to avoid collision with osv.go parser types)

type cdxOSVBatchRequest struct {
	Queries []cdxOSVQuery `json:"queries"`
}

type cdxOSVQuery struct {
	Package cdxOSVQueryPkg `json:"package"`
	Version string         `json:"version"`
}

type cdxOSVQueryPkg struct {
	PURL string `json:"purl,omitempty"`
	Name string `json:"name,omitempty"`
}

type cdxOSVBatchResponse struct {
	Results []cdxOSVQueryResult `json:"results"`
}

type cdxOSVQueryResult struct {
	Vulns []cdxOSVVuln `json:"vulns"`
}

type cdxOSVVuln struct {
	ID       string           `json:"id"`
	Aliases  []string         `json:"aliases"`
	Affected []cdxOSVAffected `json:"affected"`
}

type cdxOSVAffected struct {
	Package cdxOSVPkg   `json:"package"`
	Ranges  []cdxOSVRange `json:"ranges"`
}

type cdxOSVPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type cdxOSVRange struct {
	Type   string        `json:"type"`
	Events []cdxOSVEvent `json:"events"`
}

type cdxOSVEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

const osvBatchSize = 1000 // OSV API limit per request

// ParseCycloneDX parses a CycloneDX JSON SBOM.
// If the SBOM contains an embedded vulnerabilities list it is used directly.
// If the SBOM is a pure component manifest (no vulns), components are looked
// up in bulk via the OSV.dev batch API.
func ParseCycloneDX(r io.Reader) ([]model.Finding, error) {
	var report cdxReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("cyclonedx: invalid JSON: %w", err)
	}

	// Path 1: SBOM already contains vulnerability data — parse directly.
	if len(report.Vulnerabilities) > 0 {
		return cdxParseEmbedded(report), nil
	}

	// Path 2: Pure SBOM — query OSV.dev for each component.
	if len(report.Components) > 0 {
		return cdxLookupViaOSV(report.Components)
	}

	return nil, nil
}

// cdxParseEmbedded converts embedded CycloneDX vulnerability entries into Findings.
func cdxParseEmbedded(report cdxReport) []model.Finding {
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
	return findings
}

// cdxLookupViaOSV queries the OSV.dev batch API for a list of CycloneDX components.
func cdxLookupViaOSV(components []cdxComponent) ([]model.Finding, error) {
	// Build query list, skipping components with no version.
	type indexedComp struct {
		idx  int
		comp cdxComponent
	}
	var queryable []indexedComp
	for i, c := range components {
		if c.Version != "" {
			queryable = append(queryable, indexedComp{i, c})
		}
	}
	if len(queryable) == 0 {
		return nil, nil
	}

	var allFindings []model.Finding

	// Chunk into batches of osvBatchSize.
	for start := 0; start < len(queryable); start += osvBatchSize {
		end := start + osvBatchSize
		if end > len(queryable) {
			end = len(queryable)
		}
		chunk := queryable[start:end]

		queries := make([]cdxOSVQuery, len(chunk))
		for i, ic := range chunk {
			q := cdxOSVQuery{Version: ic.comp.Version}
			if ic.comp.PURL != "" {
				q.Package = cdxOSVQueryPkg{PURL: ic.comp.PURL}
			} else {
				q.Package = cdxOSVQueryPkg{Name: ic.comp.Name}
			}
			queries[i] = q
		}

		results, err := doOSVBatch(queries)
		if err != nil {
			return nil, fmt.Errorf("osv batch query: %w", err)
		}

		for i, res := range results {
			comp := chunk[i].comp
			eco := cdxEcosystem(comp.PURL)
			for _, v := range res.Vulns {
				id := cdxOSVPreferCVE(v.ID, v.Aliases)
				f := model.Finding{
					ID:        id,
					Package:   comp.Name,
					Version:   comp.Version,
					Ecosystem: eco,
					FixedIn:   cdxOSVExtractFixes(v.Affected, comp.Name),
					Source:    "cyclonedx",
				}
				allFindings = append(allFindings, f)
			}
		}
	}

	return allFindings, nil
}

// doOSVBatch POSTs a batch of queries to the OSV.dev API and returns results.
func doOSVBatch(queries []cdxOSVQuery) ([]cdxOSVQueryResult, error) {
	body, err := json.Marshal(cdxOSVBatchRequest{Queries: queries})
	if err != nil {
		return nil, err
	}

	resp, err := osvHTTPClient.Post(osvQueryBatchURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("contacting OSV API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned HTTP %d", resp.StatusCode)
	}

	var batch cdxOSVBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
		return nil, fmt.Errorf("decoding OSV response: %w", err)
	}

	// OSV returns results in the same order as queries; pad with empty if short.
	for len(batch.Results) < len(queries) {
		batch.Results = append(batch.Results, cdxOSVQueryResult{})
	}
	return batch.Results, nil
}

// cdxOSVPreferCVE returns the CVE alias if present, otherwise the OSV/GHSA ID.
func cdxOSVPreferCVE(id string, aliases []string) string {
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return id
}

// cdxOSVExtractFixes pulls fixed versions from OSV affected ranges for the given package.
func cdxOSVExtractFixes(affected []cdxOSVAffected, pkgName string) []string {
	seen := map[string]bool{}
	var fixes []string
	for _, a := range affected {
		if a.Package.Name != "" && !strings.EqualFold(a.Package.Name, pkgName) {
			continue
		}
		for _, rng := range a.Ranges {
			if rng.Type != "ECOSYSTEM" && rng.Type != "SEMVER" {
				continue
			}
			for _, ev := range rng.Events {
				if ev.Fixed != "" && !seen[ev.Fixed] {
					fixes = append(fixes, ev.Fixed)
					seen[ev.Fixed] = true
				}
			}
		}
	}
	return fixes
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
