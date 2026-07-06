package enrich

// VulnrichmentEnricher fetches CISA Vulnrichment data (SSVC + ADP CVSS) for CVEs.
//
// CISA publishes per-CVE JSON files in the cisagov/vulnrichment GitHub repo.
// Each file is at: https://raw.githubusercontent.com/cisagov/vulnrichment/main/
//   <year>/CVE-<year>-<id>.json
//
// The JSON follows the CVE 5.0 schema. We extract:
//   - containers.adp[].metrics[].ssvcV2  (SSVC decision points)
//   - containers.adp[].metrics[].cvssV3_1 (ADP-provided CVSS when NVD lacks one)
//
// Results are cached per-CVE in ~/.cache/culler/vr/<CVE-ID>.json (24h TTL).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sumeetghimire/culler/internal/model"
)

const (
	vulnrichmentBaseURL = "https://raw.githubusercontent.com/cisagov/vulnrichment/main"
	vrCacheSubdir       = "vr"
)

// vrCVEDoc is a partial CVE 5.0 JSON document from Vulnrichment.
type vrCVEDoc struct {
	Containers struct {
		ADP []vrADPContainer `json:"adp"`
		CNA vrCNAContainer   `json:"cna"`
	} `json:"containers"`
}

type vrADPContainer struct {
	Title   string      `json:"title"`
	Metrics []vrMetric  `json:"metrics"`
}

type vrCNAContainer struct {
	Metrics []vrMetric `json:"metrics"`
}

type vrMetric struct {
	// SSVC
	Other *vrSSVCOther `json:"other"`
	// CVSS v3.1 from ADP
	CVSSV31 *vrCVSSV31 `json:"cvssV3_1"`
}

type vrSSVCOther struct {
	Type    string      `json:"type"`
	Content vrSSVCContent `json:"content"`
}

type vrSSVCContent struct {
	Options []vrSSVCOption `json:"options"`
}

type vrSSVCOption struct {
	Exploitation    string `json:"Exploitation"`
	Automatable     string `json:"Automatable"`
	TechnicalImpact string `json:"Technical Impact"`
}

type vrCVSSV31 struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
	Source       string  `json:"source"`
}

// VulnrichmentEnricher enriches findings with CISA Vulnrichment SSVC and ADP CVSS data.
type VulnrichmentEnricher struct {
	offline bool
	cache   map[string]*vrResult // in-memory cache for this run
}

type vrResult struct {
	SSVC *model.SSVCInfo
	CVSS *model.CVSSInfo
}

// NewVulnrichmentEnricher creates an enricher. Call Enrich() directly — no pre-load needed.
func NewVulnrichmentEnricher(offline bool) *VulnrichmentEnricher {
	return &VulnrichmentEnricher{
		offline: offline,
		cache:   make(map[string]*vrResult),
	}
}

// Enrich fetches Vulnrichment data for a finding (cached per CVE).
func (v *VulnrichmentEnricher) Enrich(ef *model.EnrichedFinding) {
	id := ef.ID
	if !strings.HasPrefix(id, "CVE-") {
		return // Only CVE IDs are in Vulnrichment
	}

	res, err := v.fetchCVE(id)
	if err != nil || res == nil {
		return
	}

	if res.SSVC != nil {
		ef.SSVC = res.SSVC
	}

	// Fill CVSS gap: if the finding has no CVSS and Vulnrichment has one, use it.
	if ef.Finding.CVSS == nil && res.CVSS != nil {
		ef.Finding.CVSS = res.CVSS
	}
}

func (v *VulnrichmentEnricher) fetchCVE(id string) (*vrResult, error) {
	if res, ok := v.cache[id]; ok {
		return res, nil
	}

	// Check disk cache first
	path, err := vrDiskCachePath(id)
	if err != nil {
		return nil, err
	}

	var doc vrCVEDoc
	if age := diskAge(path); age < cacheTTL {
		// Use disk cache
		f, err := os.Open(path)
		if err == nil {
			if err := json.NewDecoder(f).Decode(&doc); err == nil {
				f.Close()
				res := parseVRDoc(&doc)
				v.cache[id] = res
				return res, nil
			}
			f.Close()
		}
	}

	if v.offline {
		return nil, nil
	}

	// Download from GitHub
	url := vrURL(id)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, nil // Silently skip — not every CVE has Vulnrichment data
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		v.cache[id] = nil
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, nil
	}

	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, nil
	}

	// Write to disk cache
	if err := os.MkdirAll(filepath.Dir(path), 0755); err == nil {
		if f, err := os.Create(path); err == nil {
			json.NewEncoder(f).Encode(doc)
			f.Close()
		}
	}

	res := parseVRDoc(&doc)
	v.cache[id] = res
	return res, nil
}

// vrURL returns the raw GitHub URL for a CVE's Vulnrichment JSON.
func vrURL(cveID string) string {
	// CVE-YYYY-NNNN → year = YYYY
	parts := strings.Split(cveID, "-")
	if len(parts) < 2 {
		return ""
	}
	year := parts[1]
	return fmt.Sprintf("%s/%s/%s.json", vulnrichmentBaseURL, year, cveID)
}

func vrDiskCachePath(cveID string) (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	parts := strings.Split(cveID, "-")
	if len(parts) < 2 {
		return filepath.Join(dir, vrCacheSubdir, cveID+".json"), nil
	}
	year := parts[1]
	return filepath.Join(dir, vrCacheSubdir, year, cveID+".json"), nil
}

func diskAge(path string) time.Duration {
	info, err := os.Stat(path)
	if err != nil {
		return 999 * time.Hour
	}
	return time.Since(info.ModTime())
}

func parseVRDoc(doc *vrCVEDoc) *vrResult {
	res := &vrResult{}

	for _, adp := range doc.Containers.ADP {
		for _, m := range adp.Metrics {
			// Extract SSVC
			if m.Other != nil && strings.ToLower(m.Other.Type) == "ssvc" {
				for _, opt := range m.Other.Content.Options {
					ssvc := &model.SSVCInfo{}
					if opt.Exploitation != "" {
						ssvc.Exploitation = strings.ToLower(opt.Exploitation)
					}
					if opt.Automatable != "" {
						ssvc.Automatable = strings.ToLower(opt.Automatable)
					}
					if opt.TechnicalImpact != "" {
						ssvc.TechnicalImpact = strings.ToLower(opt.TechnicalImpact)
					}
					if ssvc.Exploitation != "" || ssvc.Automatable != "" {
						res.SSVC = ssvc
					}
				}
			}
			// Extract ADP CVSS
			if m.CVSSV31 != nil && m.CVSSV31.BaseScore > 0 && res.CVSS == nil {
				src := "cna"
				if m.CVSSV31.Source != "" {
					src = m.CVSSV31.Source
				}
				res.CVSS = &model.CVSSInfo{
					Score:      m.CVSSV31.BaseScore,
					Vector:     m.CVSSV31.VectorString,
					Version:    "3.1",
					Provenance: src,
				}
			}
		}
	}
	return res
}
