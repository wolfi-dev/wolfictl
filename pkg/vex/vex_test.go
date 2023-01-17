package vex

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"chainguard.dev/melange/pkg/build"
	"github.com/google/go-cmp/cmp"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/require"
)

func TestSBOM(t *testing.T) {
	sbom, err := parseSBOM(context.Background(), "testdata/git.spdx.json")
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

	const defaultTimestampRFC3339 = "2022-12-01T13:10:00+07:00"
	os.Setenv("SOURCE_DATE_EPOCH", defaultTimestampRFC3339)

	doc, err := FromPackageConfiguration(vexCfg, buildCfg)
	require.NoError(t, err)

	timePointer := func(t time.Time) *time.Time { return &t }
	tz := time.FixedZone("-0500", -5*3600)

	defaultTimestamp, err := time.Parse(time.RFC3339, defaultTimestampRFC3339)
	require.NoError(t, err)

	expectedGitProducts := []string{
		"pkg:apk/wolfi/git@2.39.0-r0",
		"pkg:apk/wolfi/git-daemon@2.39.0-r0",
		"pkg:apk/wolfi/git-email@2.39.0-r0",
	}

	expected := &vex.VEX{
		Metadata: vex.Metadata{
			ID:        "vex-3702f2c3962eb7e8f8dedda72621ebf9116087a824a5aad31507d95e2cb54a88",
			Timestamp: timePointer(defaultTimestamp),
		},
		Statements: []vex.Statement{
			{
				Vulnerability: "CVE-1234-5678",
				Products:      expectedGitProducts,
				Status:        "not_affected",
				Timestamp:     timePointer(defaultTimestamp),
			},
			{
				Vulnerability: "CVE-2022-1111",
				Timestamp:     timePointer(time.Date(2022, 12, 23, 1, 28, 16, 0, tz)),
				Products:      expectedGitProducts,
				Status:        "under_investigation",
			},
			{
				Vulnerability: "CVE-2022-1111",
				Timestamp:     timePointer(time.Date(2022, 12, 23, 2, 11, 57, 0, tz)),
				Products:      expectedGitProducts,
				Status:        "not_affected",
				Justification: "component_not_present",
			},
			{
				Vulnerability: "CVE-2022-2222",
				Timestamp:     timePointer(time.Date(2022, 12, 24, 1, 28, 16, 0, tz)),
				Products:      expectedGitProducts,
				Status:        "under_investigation",
			},
			{
				Vulnerability:   "CVE-2022-2222",
				Timestamp:       timePointer(time.Date(2022, 12, 24, 2, 12, 49, 0, tz)),
				Products:        expectedGitProducts,
				Status:          "affected",
				ActionStatement: "action statement",
			},
			{
				Vulnerability: "CVE-2022-2222",
				Timestamp:     timePointer(time.Date(2022, 12, 24, 2, 50, 18, 0, tz)),
				Products:      expectedGitProducts,
				Status:        "fixed",
			},
			{
				Vulnerability: "CVE-2022-39253",
				Products:      expectedGitProducts,
				Status:        "fixed",
				Timestamp:     timePointer(defaultTimestamp),
			},
			{
				Vulnerability: "CVE-2022-39260",
				Products:      expectedGitProducts,
				Status:        "fixed",
				Timestamp:     timePointer(defaultTimestamp),
			},
		},
	}

	if diff := cmp.Diff(expected, doc); diff != "" {
		t.Errorf("Unexpected result from FromPackageConfiguration (-want, +got):\n%s", diff)
	}
}
