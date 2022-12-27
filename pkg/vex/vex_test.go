package vex

import (
	"path/filepath"
	"testing"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/vex/pkg/vex"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestFromPackageConfiguration(t *testing.T) {
	buildCfg, err := build.ParseConfiguration(filepath.Join("testdata", "git.yaml"))
	if err != nil {
		return
	}
	vexCfg := Config{
		Distro: "wolfi",
	}

	doc, err := FromPackageConfiguration(buildCfg, vexCfg)
	require.NoError(t, err)

	// zero out non-deterministic fields
	doc.ID = ""
	doc.Timestamp = nil

	expected := vex.VEX{
		Metadata: vex.Metadata{
			Format: "text/vex+json",
		},
		Statements: []vex.Statement{
			{
				Vulnerability: "CVE-1234-5678",
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-email@2.39.0-r0?distro=wolfi",
				},
				Status: "not_affected",
			},
			{
				Vulnerability: "CVE-2022-1111",
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-email@2.39.0-r0?distro=wolfi",
				},
				Status: "under_investigation",
			},
			{
				Vulnerability: "CVE-2022-1111",
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-email@2.39.0-r0?distro=wolfi",
				},
				Status:        "not_affected",
				Justification: "component_not_present",
			},
			{
				Vulnerability: "CVE-2022-2222",
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-email@2.39.0-r0?distro=wolfi",
				},
				Status: "under_investigation",
			},
			{
				Vulnerability: "CVE-2022-2222",
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-email@2.39.0-r0?distro=wolfi",
				},
				Status:          "affected",
				ActionStatement: "action statement",
			},
			{
				Vulnerability: "CVE-2022-2222",
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-email@2.39.0-r0?distro=wolfi",
				},
				Status: "fixed",
			},
			{
				Vulnerability: "CVE-2022-39253",
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-email@2.39.0-r0?distro=wolfi",
				},
				Status: "fixed",
			},
			{
				Vulnerability: "CVE-2022-39260",
				Products: []string{
					"pkg:apk/wolfi/git@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-daemon@2.39.0-r0?distro=wolfi",
					"pkg:apk/wolfi/git-email@2.39.0-r0?distro=wolfi",
				},
				Status: "fixed",
			},
		},
	}

	if diff := cmp.Diff(expected, doc); diff != "" {
		t.Errorf("Unexpected result from FromPackageConfiguration (-want, +got):\n%s", diff)
	}
}
