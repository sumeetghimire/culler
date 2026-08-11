package parsers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Embedded vulnerabilities path ────────────────────────────────────────────

func TestParseCycloneDX_Embedded(t *testing.T) {
	f, err := os.Open("../../testdata/cyclonedx.json")
	require.NoError(t, err)
	defer f.Close()

	findings, err := ParseCycloneDX(f)
	require.NoError(t, err)
	assert.Len(t, findings, 3)

	struts := findings[0]
	assert.Equal(t, "CVE-2023-50164", struts.ID)
	assert.Equal(t, "struts2-core", struts.Package)
	assert.Equal(t, "2.5.30", struts.Version)
	assert.Equal(t, "maven", struts.Ecosystem)
	require.NotNil(t, struts.CVSS)
	assert.Equal(t, 9.8, struts.CVSS.Score)
}

// ── Pure SBOM → OSV batch lookup path ────────────────────────────────────────

func TestParseCycloneDX_PureSBOM_OSVLookup(t *testing.T) {
	// Serve a fake OSV batch response
	osvResp := cdxOSVBatchResponse{
		Results: []cdxOSVQueryResult{
			{
				Vulns: []cdxOSVVuln{
					{
						ID:      "GHSA-4w2v-q235-vp99",
						Aliases: []string{"CVE-2021-3749"},
						Affected: []cdxOSVAffected{
							{
								Package: cdxOSVPkg{Name: "axios", Ecosystem: "npm"},
								Ranges: []cdxOSVRange{
									{
										Type: "ECOSYSTEM",
										Events: []cdxOSVEvent{
											{Introduced: "0"},
											{Fixed: "0.21.2"},
										},
									},
								},
							},
						},
					},
				},
			},
			{
				Vulns: []cdxOSVVuln{
					{
						ID:      "GHSA-qm57-vhq3-3fwf",
						Aliases: []string{"CVE-2023-41164"},
						Affected: []cdxOSVAffected{
							{
								Package: cdxOSVPkg{Name: "Django", Ecosystem: "PyPI"},
								Ranges: []cdxOSVRange{
									{
										Type: "ECOSYSTEM",
										Events: []cdxOSVEvent{
											{Introduced: "3.2"},
											{Fixed: "3.2.21"},
										},
									},
								},
							},
						},
					},
				},
			},
			// lodash has version="" so it should be skipped — OSV gets 2 queries not 3
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/querybatch", r.URL.Path)

		var req cdxOSVBatchRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		// lodash has empty version, should be excluded
		assert.Len(t, req.Queries, 2)
		assert.Equal(t, "pkg:npm/axios@0.21.1", req.Queries[0].Package.PURL)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(osvResp))
	}))
	defer srv.Close()

	origURL := osvQueryBatchURL
	origClient := osvHTTPClient
	osvQueryBatchURL = srv.URL + "/v1/querybatch"
	osvHTTPClient = srv.Client()
	defer func() {
		osvQueryBatchURL = origURL
		osvHTTPClient = origClient
	}()

	f, err := os.Open("../../testdata/cyclonedx_sbom.json")
	require.NoError(t, err)
	defer f.Close()

	findings, err := ParseCycloneDX(f)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	assert.Equal(t, "CVE-2021-3749", findings[0].ID)
	assert.Equal(t, "axios", findings[0].Package)
	assert.Equal(t, "0.21.1", findings[0].Version)
	assert.Equal(t, "npm", findings[0].Ecosystem)
	assert.Equal(t, []string{"0.21.2"}, findings[0].FixedIn)
	assert.Equal(t, "cyclonedx", findings[0].Source)

	assert.Equal(t, "CVE-2023-41164", findings[1].ID)
	assert.Equal(t, "Django", findings[1].Package)
}

func TestParseCycloneDX_PureSBOM_OSVError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	origURL := osvQueryBatchURL
	origClient := osvHTTPClient
	osvQueryBatchURL = srv.URL + "/v1/querybatch"
	osvHTTPClient = srv.Client()
	defer func() {
		osvQueryBatchURL = origURL
		osvHTTPClient = origClient
	}()

	f, err := os.Open("../../testdata/cyclonedx_sbom.json")
	require.NoError(t, err)
	defer f.Close()

	_, err = ParseCycloneDX(f)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OSV API returned HTTP 500")
}

func TestParseCycloneDX_EmptySBOM(t *testing.T) {
	input := `{"bomFormat":"CycloneDX","specVersion":"1.5"}`
	findings, err := ParseCycloneDX(strings.NewReader(input))
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParseCycloneDX_NoVersionComponents(t *testing.T) {
	// Components with no version should be silently skipped (no OSV query sent).
	// We verify by pointing at a server that would fail if called.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("OSV API should not be called when no components have versions")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	origURL := osvQueryBatchURL
	origClient := osvHTTPClient
	osvQueryBatchURL = srv.URL + "/v1/querybatch"
	osvHTTPClient = srv.Client()
	defer func() {
		osvQueryBatchURL = origURL
		osvHTTPClient = origClient
	}()

	input := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"foo","version":""}]}`
	findings, err := ParseCycloneDX(strings.NewReader(input))
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// ── Helper function unit tests ────────────────────────────────────────────────

func TestOSVPreferCVE(t *testing.T) {
	assert.Equal(t, "CVE-2021-3749", cdxOSVPreferCVE("GHSA-4w2v-q235-vp99", []string{"CVE-2021-3749"}))
	assert.Equal(t, "GHSA-xxxx", cdxOSVPreferCVE("GHSA-xxxx", []string{"not-a-cve"}))
	assert.Equal(t, "GHSA-xxxx", cdxOSVPreferCVE("GHSA-xxxx", nil))
}

func TestOSVExtractFixes(t *testing.T) {
	affected := []cdxOSVAffected{
		{
			Package: cdxOSVPkg{Name: "axios", Ecosystem: "npm"},
			Ranges: []cdxOSVRange{
				{
					Type: "ECOSYSTEM",
					Events: []cdxOSVEvent{
						{Introduced: "0"},
						{Fixed: "0.21.2"},
					},
				},
			},
		},
	}
	fixes := cdxOSVExtractFixes(affected, "axios")
	assert.Equal(t, []string{"0.21.2"}, fixes)
}

func TestOSVExtractFixes_DeduplicatesAndFiltersGIT(t *testing.T) {
	affected := []cdxOSVAffected{
		{
			Package: cdxOSVPkg{Name: "pkg"},
			Ranges: []cdxOSVRange{
				{Type: "GIT", Events: []cdxOSVEvent{{Fixed: "abc123"}}},
				{Type: "ECOSYSTEM", Events: []cdxOSVEvent{{Fixed: "1.2.3"}, {Fixed: "1.2.3"}}},
			},
		},
	}
	fixes := cdxOSVExtractFixes(affected, "pkg")
	assert.Equal(t, []string{"1.2.3"}, fixes) // GIT skipped, duplicate deduped
}

func TestCycloneDXEcosystem(t *testing.T) {
	cases := []struct {
		purl, want string
	}{
		{"pkg:maven/org.apache.struts/struts2-core@2.5.30", "maven"},
		{"pkg:npm/axios@0.21.1", "npm"},
		{"pkg:pypi/django@3.2.18", "pypi"},
		{"", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, cdxEcosystem(c.purl))
	}
}
