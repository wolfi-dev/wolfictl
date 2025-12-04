package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func testPkgDefinition(epoch string) []byte {
	pkgTemplate := `
package:
  name: awesome-tool
  version: 0.61.0
  epoch: EPOCH_HERE
`
	return []byte(strings.ReplaceAll(pkgTemplate, "EPOCH_HERE", epoch))
}

func TestBumpWithComment(t *testing.T) {
	for i, td := range []struct {
		before []byte
		want   []byte
	}{
		{
			testPkgDefinition("1 # a comment!"),
			testPkgDefinition("2 # a comment!"),
		},
		{
			testPkgDefinition("1 # CVE-111-222"),
			testPkgDefinition("2"),
		},
		{
			testPkgDefinition("1 # GHSA-a1b2-c1c2"),
			testPkgDefinition("2"),
		},
	} {
		name := filepath.Join(t.TempDir(), "awesome-tool.yaml")

		if err := os.WriteFile(name, td.before, 0o644); err != nil {
			t.Fatal(err)
		}

		if err := bumpEpoch(t.Context(), bumpOptions{}, name); err != nil {
			t.Fatal(err)
		}

		got, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(got, td.want); diff != "" {
			t.Errorf("%d - bumpEpoch() mismatch (-want +got):\n%s", i, diff)
		}
	}
}
