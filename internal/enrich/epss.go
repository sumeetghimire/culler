package enrich

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sumeetghimire/culler/internal/model"
)

const (
	epssURL       = "https://epss.cyentia.com/epss_scores-current.csv.gz"
	epssCacheFile = "epss_scores.csv.gz"
)

type epssScore struct {
	Score      float64
	Percentile float64
}

// EPSSEnricher looks up FIRST EPSS scores for findings.
type EPSSEnricher struct {
	scores   map[string]epssScore // keyed by CVE ID
	feedDate time.Time
}

// Load initialises the enricher from cache (refreshing if stale).
func (e *EPSSEnricher) Load(offline bool) error {
	age := cacheAge(epssCacheFile)
	needsRefresh := age > cacheTTL

	if needsRefresh && !offline {
		if err := downloadRaw(epssURL, epssCacheFile, "FIRST EPSS"); err != nil {
			if age < 999*time.Hour {
				fmt.Fprintf(os.Stderr, "  Warning: could not refresh EPSS (using cached copy from %.0fh ago)\n", age.Hours())
			} else {
				return fmt.Errorf("EPSS feed unavailable and no cache: %w", err)
			}
		}
	} else if offline && age >= 999*time.Hour {
		return fmt.Errorf("--offline requested but EPSS cache is missing; run `culler update` first")
	}

	if err := e.parseCSVGz(); err != nil {
		return fmt.Errorf("loading EPSS cache: %w", err)
	}

	path, _ := cacheFile(epssCacheFile)
	if info, err := os.Stat(path); err == nil {
		e.feedDate = info.ModTime()
	}
	return nil
}

func (e *EPSSEnricher) parseCSVGz() error {
	path, err := rawCachePath(epssCacheFile)
	if err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening EPSS cache: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("decompressing EPSS cache: %w", err)
	}
	defer gz.Close()

	return e.parseCSV(gz)
}

func (e *EPSSEnricher) parseCSV(r io.Reader) error {
	// The EPSS CSV starts with a comment line like:
	// #model_version:v2023.03.01,score_date:2024-01-15T00:00:00+0000
	// followed by header: cve,epss,percentile
	// followed by data rows.

	// Read all into a buffer so we can skip the comment line.
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	// Strip leading comment lines (start with '#')
	lines := strings.SplitN(string(data), "\n", -1)
	var cleanLines []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "#") {
			cleanLines = append(cleanLines, l)
		}
	}

	cr := csv.NewReader(strings.NewReader(strings.Join(cleanLines, "\n")))
	cr.ReuseRecord = true

	// Read header
	header, err := cr.Read()
	if err != nil {
		return fmt.Errorf("reading EPSS CSV header: %w", err)
	}
	// Expect: cve, epss, percentile
	if len(header) < 3 {
		return fmt.Errorf("unexpected EPSS CSV header: %v", header)
	}

	e.scores = make(map[string]epssScore, 250000)
	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading EPSS CSV: %w", err)
		}
		if len(row) < 3 {
			continue
		}
		cve := row[0]
		score, err1 := strconv.ParseFloat(row[1], 64)
		pct, err2 := strconv.ParseFloat(row[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		e.scores[cve] = epssScore{Score: score, Percentile: pct}
	}
	return nil
}

// Enrich annotates an EnrichedFinding with its EPSS score.
func (e *EPSSEnricher) Enrich(ef *model.EnrichedFinding) {
	s, ok := e.scores[ef.ID]
	if !ok {
		return
	}
	ef.EPSS = model.EPSSInfo{
		Score:      s.Score,
		Percentile: s.Percentile,
	}
}

// FeedDate returns when the EPSS cache was last refreshed.
func (e *EPSSEnricher) FeedDate() time.Time { return e.feedDate }

// Count returns the number of EPSS entries loaded.
func (e *EPSSEnricher) Count() int { return len(e.scores) }
