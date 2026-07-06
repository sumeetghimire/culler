package enrich

import (
	"fmt"
	"os"
	"time"

	"github.com/sumeetghimire/culler/internal/model"
)

const (
	kevURL       = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevCacheFile = "kev.json"
)

type kevFeed struct {
	Title           string     `json:"title"`
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
	CveID                      string `json:"cveID"`
	DateAdded                  string `json:"dateAdded"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

// KEVEnricher checks findings against the CISA Known Exploited Vulnerabilities catalog.
type KEVEnricher struct {
	entries  map[string]kevEntry // keyed by CVE ID
	feedDate time.Time
}

// Load initialises the enricher from cache (refreshing if stale).
// If offline is true, only the cache is used; an error is returned if missing.
func (k *KEVEnricher) Load(offline bool) error {
	age := cacheAge(kevCacheFile)
	needsRefresh := age > cacheTTL

	if needsRefresh && !offline {
		if err := downloadRaw(kevURL, kevCacheFile, "CISA KEV"); err != nil {
			if age < 999*time.Hour {
				fmt.Fprintf(os.Stderr, "  Warning: could not refresh KEV (using cached copy from %.0fh ago)\n", age.Hours())
			} else {
				return fmt.Errorf("KEV feed unavailable and no cache: %w", err)
			}
		}
	} else if offline && age >= 999*time.Hour {
		return fmt.Errorf("--offline requested but KEV cache is missing; run `culler update` first")
	}

	var feed kevFeed
	if err := loadJSON(kevCacheFile, &feed); err != nil {
		return fmt.Errorf("loading KEV cache: %w", err)
	}

	k.entries = make(map[string]kevEntry, len(feed.Vulnerabilities))
	for _, e := range feed.Vulnerabilities {
		k.entries[e.CveID] = e
	}

	path, _ := cacheFile(kevCacheFile)
	if info, err := os.Stat(path); err == nil {
		k.feedDate = info.ModTime()
	}
	return nil
}

// Enrich annotates an EnrichedFinding with KEV membership data.
func (k *KEVEnricher) Enrich(ef *model.EnrichedFinding) {
	e, ok := k.entries[ef.ID]
	if !ok {
		return
	}
	ef.KEV = model.KEVInfo{
		InKEV:              true,
		DateAdded:          e.DateAdded,
		RansomwareCampaign: e.KnownRansomwareCampaignUse == "Known",
	}
}

// FeedDate returns when the KEV cache was last refreshed.
func (k *KEVEnricher) FeedDate() time.Time { return k.feedDate }

// Count returns the number of KEV entries loaded.
func (k *KEVEnricher) Count() int { return len(k.entries) }
