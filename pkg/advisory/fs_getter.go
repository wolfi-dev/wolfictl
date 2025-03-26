package advisory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

// assert that FSGetter implements Getter
var _ Getter = (*FSGetter)(nil)

// FSGetter is a getter that loads advisory data from YAML files in an
// fs.FS on-demand, avoiding file opens/reads until needed.
type FSGetter struct {
	fsys fs.FS
}

func NewFSGetter(fsys fs.FS) *FSGetter {
	return &FSGetter{
		fsys: fsys,
	}
}

func (g FSGetter) PackageNames(_ context.Context) ([]string, error) {
	// We'll trust the file names as authoritative for the referenced package name.
	// If we find this to be insufficient, we can evolve to a partial decode of the
	// document, but that will use more memory and be slower.

	entries, err := fs.ReadDir(g.fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("reading directory: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".advisories.yaml") {
			continue
		}
		names = append(names, strings.TrimSuffix(entry.Name(), ".advisories.yaml"))
	}

	return names, nil
}

func (g FSGetter) Advisories(_ context.Context, packageName string) ([]v2.PackageAdvisory, error) {
	advFileName := fmt.Sprintf("%s.advisories.yaml", packageName)
	f, err := g.fsys.Open(advFileName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// This is normal, just no advisories for this package.
			return nil, nil
		}

		return nil, fmt.Errorf("opening advisory file %q: %w", advFileName, err)
	}

	doc, err := v2.DecodeDocument(f)
	if err != nil {
		return nil, fmt.Errorf("decoding advisory file %q: %w", advFileName, err)
	}

	result := make([]v2.PackageAdvisory, 0, len(doc.Advisories))
	for _, adv := range doc.Advisories {
		result = append(result, v2.PackageAdvisory{
			PackageName: packageName,
			Advisory: v2.Advisory{
				ID:      adv.ID,
				Aliases: adv.Aliases,
				Events:  adv.Events,
			},
		})
	}

	return result, nil
}
