package parsers

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOSV(t *testing.T) {
	f, err := os.Open("../../testdata/osv.json")
	require.NoError(t, err)
	defer f.Close()

	findings, err := ParseOSV(f)
	require.NoError(t, err)
	assert.Len(t, findings, 3)

	// CVE alias should be preferred over GHSA
	pillow := findings[0]
	assert.Equal(t, "CVE-2023-44271", pillow.ID)
	assert.Equal(t, "Pillow", pillow.Package)
	assert.Equal(t, "9.3.0", pillow.Version)
	assert.Equal(t, "PyPI", pillow.Ecosystem)
	assert.Equal(t, []string{"10.0.0"}, pillow.FixedIn)
	assert.Equal(t, "osv", pillow.Source)
}
