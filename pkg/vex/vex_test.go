package vex

import (
	"path/filepath"
	"testing"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/vex/pkg/vex"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
)

func TestSBOM(t *testing.T) {
	sbom, err := parseSBOM("testdata/git.spdx.json")
	require.NoError(t, err)

	purls := extractSBOMPurls(Config{Distro: "wolfi"}, sbom)

	// Check the list is right:
	require.Len(t, purls, 1)
	purlList, ok := purls["pkg:oci/git@sha256:54a88f29b889d82e57712206973db99089caf4074232bb16df8c72605aaaa410?arch=amd64\u0026mediaType=application%2Fvnd.oci.image.manifest.v1%2Bjson\u0026os=linux"]
	require.True(t, ok)
	require.Len(t, purlList, 13)
}

func TestIndexMelangeConfigsDir(t *testing.T) {
	files, err := indexMelangeConfigsDir("testdata/configs/")
	require.NoError(t, err)
	require.Len(t, files, 218)
}

func TestFromPackageConfiguration(t *testing.T) {
	buildCfg, err := build.ParseConfiguration(filepath.Join("testdata", "git.yaml"))
	require.NoError(t, err)

	vexCfg := Config{
		Distro: "wolfi",
	}

	doc, err := FromPackageConfiguration(vexCfg, buildCfg)
	require.NoError(t, err)

	// zero out non-deterministic fields
	doc.Timestamp = nil
	doc.ID = ""

	// TODO: re-introduce timestamp comparisons once latest version of VEX module is imported

	expected := &vex.VEX{
		Metadata: vex.Metadata{
			Format: "text/vex",
		},
		Statements: []vex.Statement{
			{
				Vulnerability: "CVE-1234-5678",
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0",
					"pkg:apk/wolfi/git-email@2.39.0-r0",
				},
				Status: "not_affected",
			},
			{
				Vulnerability: "CVE-2022-1111",
				// Timestamp:     timePointer(time.Date(2022, 12, 23, 1, 28, 16, 0, tz)),
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0",
					"pkg:apk/wolfi/git-email@2.39.0-r0",
				},
				Status: "under_investigation",
			},
			{
				Vulnerability: "CVE-2022-1111",
				// Timestamp:     timePointer(time.Date(2022, 12, 23, 2, 11, 57, 0, tz)),
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0",
					"pkg:apk/wolfi/git-email@2.39.0-r0",
				},
				Status:        "not_affected",
				Justification: "component_not_present",
			},
			{
				Vulnerability: "CVE-2022-2222",
				// Timestamp:     timePointer(time.Date(2022, 12, 24, 1, 28, 16, 0, tz)),
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0",
					"pkg:apk/wolfi/git-email@2.39.0-r0",
				},
				Status: "under_investigation",
			},
			{
				Vulnerability: "CVE-2022-2222",
				// Timestamp:     timePointer(time.Date(2022, 12, 24, 2, 12, 49, 0, tz)),
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0",
					"pkg:apk/wolfi/git-email@2.39.0-r0",
				},
				Status:          "affected",
				ActionStatement: "action statement",
			},
			{
				Vulnerability: "CVE-2022-2222",
				// Timestamp:     timePointer(time.Date(2022, 12, 24, 2, 50, 18, 0, tz)),
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0",
					"pkg:apk/wolfi/git-email@2.39.0-r0",
				},
				Status: "fixed",
			},
			{
				Vulnerability: "CVE-2022-39253",
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0",
					"pkg:apk/wolfi/git-email@2.39.0-r0",
				},
				Status: "fixed",
			},
			{
				Vulnerability: "CVE-2022-39260",
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0",
					"pkg:apk/wolfi/git-email@2.39.0-r0",
				},
				Status: "fixed",
			},
		},
	}

	if diff := cmp.Diff(expected, doc, cmpopts.IgnoreFields(vex.Statement{}, "Timestamp")); diff != "" {
		t.Errorf("Unexpected result from FromPackageConfiguration (-want, +got):\n%s", diff)
	}
}
