package parsers

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTrivy(t *testing.T) {
	f, err := os.Open("../../testdata/trivy.json")
	require.NoError(t, err)
	defer f.Close()

	findings, err := ParseTrivy(f)
	require.NoError(t, err)
	assert.Len(t, findings, 4)

	// loader-utils — first finding
	ldr := findings[0]
	assert.Equal(t, "CVE-2022-37601", ldr.ID)
	assert.Equal(t, "loader-utils", ldr.Package)
	assert.Equal(t, "1.4.0", ldr.Version)
	assert.Equal(t, "npm", ldr.Ecosystem)
	assert.Equal(t, []string{"1.4.2"}, ldr.FixedIn)
	require.NotNil(t, ldr.CVSS)
	assert.Equal(t, 9.8, ldr.CVSS.Score)
	assert.Equal(t, "nvd", ldr.CVSS.Provenance)
}

func TestParseTrivyEcosystem(t *testing.T) {
	cases := []struct {
		typ, want string
	}{
		{"jar", "maven"},
		{"gomodule", "go"},
		{"npm", "npm"},
		{"pip", "pypi"},
		{"ubuntu", "deb"},
		{"alpine", "apk"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, trivyEcosystem(c.typ))
	}
}
