package enrich

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const cacheTTL = 24 * time.Hour

var httpClient = &http.Client{
	Timeout: 60 * time.Second,
}

// cacheDir returns (and creates if needed) ~/.cache/culler/
func cacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".cache", "culler")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("cannot create cache directory %s: %w", dir, err)
	}
	return dir, nil
}

// cacheFile returns the full path to a named cache file.
func cacheFile(name string) (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// cacheAge returns the age of a cache file. Returns a very large duration if missing.
func cacheAge(name string) time.Duration {
	path, err := cacheFile(name)
	if err != nil {
		return 999 * time.Hour
	}
	info, err := os.Stat(path)
	if err != nil {
		return 999 * time.Hour
	}
	return time.Since(info.ModTime())
}

// FeedAge returns a human-readable age string for a named cache file.
func FeedAge(name string) string {
	age := cacheAge(name)
	if age >= 999*time.Hour {
		return "not cached"
	}
	h := int(age.Hours())
	if h < 1 {
		return fmt.Sprintf("%dm ago", int(age.Minutes()))
	}
	return fmt.Sprintf("%dh ago", h)
}

// DeleteCache removes a named cache file (used by `culler update` to force refresh).
func DeleteCache(name string) {
	path, err := cacheFile(name)
	if err != nil {
		return
	}
	os.Remove(path)
}

// loadJSON reads a JSON-encoded cache file into v.
func loadJSON(name string, v interface{}) error {
	path, err := cacheFile(name)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cache miss for %s: %w", name, err)
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(v)
}

// downloadRaw fetches a URL and writes the raw bytes to a cache file,
// printing a progress message to stderr.
func downloadRaw(url, name, label string) error {
	fmt.Fprintf(os.Stderr, "  Downloading %s...", label)
	resp, err := httpClient.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, " failed")
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, " failed")
		return fmt.Errorf("downloading %s: HTTP %d", url, resp.StatusCode)
	}

	path, err := cacheFile(name)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("cannot write cache file %s: %w", path, err)
	}
	n, err := io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		os.Remove(tmp)
		fmt.Fprintln(os.Stderr, " failed")
		return fmt.Errorf("writing cache file %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, " done (%.1f KB)\n", float64(n)/1024)
	return nil
}

// rawCachePath returns the path to a raw (non-JSON) cache file.
func rawCachePath(name string) (string, error) {
	return cacheFile(name)
}

// LastScanPath returns the path to the persisted last-scan JSON used by `explain`.
func LastScanPath() (string, error) {
	return cacheFile("last_scan.json")
}
