// Package policy loads and applies .culler.yaml scan policy.
package policy

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sumeetghimire/culler/internal/model"
)

// Config is the structure of .culler.yaml.
type Config struct {
	InternetFacing bool          `yaml:"internet_facing"` // bump tier one level if true
	Ignore         []IgnoreEntry `yaml:"ignore"`
	Thresholds     *Thresholds   `yaml:"thresholds"`
}

// IgnoreEntry suppresses a CVE with a required reason.
type IgnoreEntry struct {
	ID      string `yaml:"id"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires"` // optional YYYY-MM-DD
}

// Thresholds lets users override decision-engine cutoffs.
type Thresholds struct {
	EPSSActNow     float64 `yaml:"epss_act_now"`
	EPSSOutOfCycle float64 `yaml:"epss_out_of_cycle"`
	EPSSPercentile float64 `yaml:"epss_percentile"`
	CVSSScheduled  float64 `yaml:"cvss_scheduled"`
}

// Load reads a policy file. Returns an empty Config (not an error) if missing.
func Load(path string) (*Config, error) {
	if path == "" {
		path = ".culler.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("reading policy file %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing policy file %s: %w", path, err)
	}
	return &cfg, nil
}

// Apply filters and adjusts findings according to policy.
// Returns the filtered slice and a list of suppressed finding IDs.
func Apply(findings []model.EnrichedFinding, cfg *Config) ([]model.EnrichedFinding, []string) {
	if cfg == nil {
		return findings, nil
	}

	ignoreMap := buildIgnoreMap(cfg.Ignore)
	var result []model.EnrichedFinding
	var suppressed []string

	for _, f := range findings {
		if ig, ok := ignoreMap[f.ID]; ok {
			if !isExpired(ig.Expires) {
				suppressed = append(suppressed, fmt.Sprintf("%s (reason: %s)", f.ID, ig.Reason))
				continue
			}
		}

		// Internet-facing bump: advance tier by one level
		if cfg.InternetFacing && f.Tier > model.TierActNow {
			f.Tier--
			f.Reasoning = append(f.Reasoning, "bumped one tier (internet_facing=true)")
		}

		result = append(result, f)
	}
	return result, suppressed
}

func buildIgnoreMap(entries []IgnoreEntry) map[string]IgnoreEntry {
	m := make(map[string]IgnoreEntry, len(entries))
	for _, e := range entries {
		m[e.ID] = e
	}
	return m
}

func isExpired(dateStr string) bool {
	if dateStr == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return false
	}
	return time.Now().After(t)
}
