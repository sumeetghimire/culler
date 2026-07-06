package parsers

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCycloneDX(t *testing.T) {
	f, err := os.Open("../../testdata/cyclonedx.json")
	require.NoError(t, err)
	defer f.Close()

	findings, err := ParseCycloneDX(f)
	require.NoError(t, err)
	assert.Len(t, findings, 3)

	// Struts RCE
	struts := findings[0]
	assert.Equal(t, "CVE-2023-50164", struts.ID)
	assert.Equal(t, "struts2-core", struts.Package)
	assert.Equal(t, "2.5.30", struts.Version)
	assert.Equal(t, "maven", struts.Ecosystem)
	require.NotNil(t, struts.CVSS)
	assert.Equal(t, 9.8, struts.CVSS.Score)
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
