package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBumpWithComment(t *testing.T) {
	before := []byte(`
package:
  name: awesome-tool
  version: 0.61.0
  epoch: 1 # a comment!
`)

	want := []byte(`
package:
  name: awesome-tool
  version: 0.61.0
  epoch: 2 # a comment!
`)

	name := filepath.Join(t.TempDir(), "awesome-tool.yaml")

	if err := os.WriteFile(name, before, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := bumpEpoch(t.Context(), bumpOptions{}, name); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("bumpEpoch() mismatch (-want +got):\n%s", diff)
	}
}
