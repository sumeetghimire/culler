package parsers

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGrype(t *testing.T) {
	f, err := os.Open("../../testdata/grype.json")
	require.NoError(t, err)
	defer f.Close()

	findings, err := ParseGrype(f)
	require.NoError(t, err)
	assert.Len(t, findings, 10)

	// Spot-check Log4Shell
	log4j := findings[0]
	assert.Equal(t, "CVE-2021-44228", log4j.ID)
	assert.Equal(t, "log4j-core", log4j.Package)
	assert.Equal(t, "2.14.1", log4j.Version)
	assert.Equal(t, "maven", log4j.Ecosystem)
	assert.Equal(t, []string{"2.15.0"}, log4j.FixedIn)
	assert.Equal(t, "grype", log4j.Source)
	assert.Equal(t, "Critical", log4j.Severity)
	require.NotNil(t, log4j.CVSS)
	assert.Equal(t, 10.0, log4j.CVSS.Score)
	assert.Equal(t, "nvd", log4j.CVSS.Provenance)
}

func TestDetectGrype(t *testing.T) {
	f, err := os.Open("../../testdata/grype.json")
	require.NoError(t, err)
	defer f.Close()

	findings, source, err := Parse(f)
	require.NoError(t, err)
	assert.Equal(t, "grype", source)
	assert.Len(t, findings, 10)
}

func TestDetectTrivy(t *testing.T) {
	f, err := os.Open("../../testdata/trivy.json")
	require.NoError(t, err)
	defer f.Close()

	findings, source, err := Parse(f)
	require.NoError(t, err)
	assert.Equal(t, "trivy", source)
	assert.Len(t, findings, 4)
}

func TestDetectOSV(t *testing.T) {
	f, err := os.Open("../../testdata/osv.json")
	require.NoError(t, err)
	defer f.Close()

	findings, source, err := Parse(f)
	require.NoError(t, err)
	assert.Equal(t, "osv-scanner", source)
	assert.Len(t, findings, 3)
}

func TestDetectCycloneDX(t *testing.T) {
	f, err := os.Open("../../testdata/cyclonedx.json")
	require.NoError(t, err)
	defer f.Close()

	findings, source, err := Parse(f)
	require.NoError(t, err)
	assert.Equal(t, "cyclonedx", source)
	assert.Len(t, findings, 3)
}

func TestDetectInvalidJSON(t *testing.T) {
	_, _, err := Parse(os.Stdin)
	assert.Error(t, err)
}

func TestParseGrypeEcosystem(t *testing.T) {
	cases := []struct {
		lang, typ, want string
	}{
		{"java", "java-archive", "maven"},
		{"python", "python", "pypi"},
		{"javascript", "npm", "npm"},
		{"go", "gomodule", "go"},
		{"", "deb", "deb"},
		{"", "rpm", "rpm"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, ecosystem(c.lang, c.typ), "lang=%s typ=%s", c.lang, c.typ)
	}
}
