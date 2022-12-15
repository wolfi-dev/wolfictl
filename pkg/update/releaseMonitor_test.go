package update

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReleaseMonitor_parseVersions(t *testing.T) {
	m := MonitorService{Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix)}

	tests := []struct {
		name                  string
		expectedLatestVersion string
	}{
		{name: "versions", expectedLatestVersion: "2.3.1"},
		{name: "icu_versions", expectedLatestVersion: "72-1"},
	}
	for _, tt := range tests {
		data, err := os.ReadFile(filepath.Join("testdata", tt.name+".json"))
		assert.NoError(t, err)

		t.Run(tt.name, func(t *testing.T) {
			got, err := m.parseVersions(data)
			assert.NoError(t, err)
			assert.Equalf(t, tt.expectedLatestVersion, got, "parseVersions(%v)", tt.name)
			assert.Equalf(t, tt.expectedLatestVersion, got, "parseVersions(%v)", tt.name)
		})
	}
}
