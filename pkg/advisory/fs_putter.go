package advisory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"

	cgaid "github.com/chainguard-dev/advisory-schema/pkg/advisory"
	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/chainguard-dev/yam/pkg/util"
	"github.com/chainguard-dev/yam/pkg/yam/formatted"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
)

// DocumentEncoder writes a Document to an io.Writer in a specific format.
type DocumentEncoder func(w io.Writer, doc v2.Document) error

// NewYamDocumentEncoder creates a new DocumentEncoder that uses yan
// (https://github.com/chainguard-dev/yam) to encode the document as YAML using
// the specified formatting options.
func NewYamDocumentEncoder(opts formatted.EncodeOptions) DocumentEncoder {
	return func(w io.Writer, doc v2.Document) error {
		enc := formatted.NewEncoder(w)

		var err error
		enc, err = enc.UseOptions(opts)
		if err != nil {
			return fmt.Errorf("using yam options: %w", err)
		}

		if err := enc.Encode(doc); err != nil {
			return fmt.Errorf("encoding document: %w", err)
		}

		return nil
	}
}

// FSPutter is an implementation of Putter that creates or updates an advisory
// using the given Request, operating on a `.advisories.yaml` file in the given
// filesystem.
type FSPutter struct {
	fsys        rwfs.FS
	enc         DocumentEncoder
	idGenerator cgaid.IDGenerator
}

// NewFSPutter creates and returns a new FSPutter that updates advisory data in
// the given filesystem using the provided FileEncoder to marshal and format the
// file data.
func NewFSPutter(fsys rwfs.FS, enc DocumentEncoder) *FSPutter {
	return &FSPutter{
		fsys:        fsys,
		enc:         enc,
		idGenerator: cgaid.DefaultIDGenerator,
	}
}

// NewFSPutterWithAutomaticEncoder creates and returns a new FSPutter. It
// determines the encoder configuration by attempting to use the `.yam.yaml`
// file at the root of the given `fsys`. If none is available, a default
// configuration is used for the encoder.
func NewFSPutterWithAutomaticEncoder(fsys rwfs.FS) *FSPutter {
	// We'll set defaults to be used if we can't open and use the config file.
	encodeOptions := formatted.EncodeOptions{
		Indent:         2,
		GapExpressions: []string{".", ".advisories"},
	}

	// Best-effort attempt to read the config file. If any we hit any errors, we're
	// totally fine using the above defaults.

	cfgFile, err := fsys.Open(util.ConfigFileName)
	if err == nil {
		defer cfgFile.Close()

		encodeOptionsFromFsys, err := formatted.ReadConfigFrom(cfgFile)
		if err == nil {
			encodeOptions = *encodeOptionsFromFsys
		}
	}

	return NewFSPutter(fsys, NewYamDocumentEncoder(encodeOptions))
}

func (p FSPutter) Upsert(_ context.Context, request Request) (string, error) {
	if request.Package == "" {
		return "", ErrEmptyPackage
	}

	// The advisories file might exist, or not. If it does exist, the advisory
	// itself might exist, or not.

	advisoryFileHadExisted := false

	advFileName := fmt.Sprintf("%s.advisories.yaml", request.Package)
	f, err := p.fsys.Open(advFileName)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("opening advisory file %q: %w", advFileName, err)
	}

	var doc *v2.Document
	if err == nil {
		advisoryFileHadExisted = true

		doc, err = v2.DecodeDocument(f)
		if err != nil {
			return "", fmt.Errorf("decoding advisory file %q: %w", advFileName, err)
		}
	} else {
		doc = &v2.Document{
			Package: v2.Package{
				Name: request.Package,
			},
		}
	}

	if advisoryFileHadExisted {
		// Done reading. Depending on how far we get in the logic, we'll later open the
		// file as writeable (if needed).
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("closing advisory file %q: %w", advFileName, err)
		}
	}

	// We set the schema to current whenever we're operating on the file.
	doc.SchemaVersion = v2.SchemaVersion

	// Find or create the advisory
	var advisory *v2.Advisory
	if reqID := request.AdvisoryID; reqID != "" {
		adv, exists := doc.Advisories.Get(reqID)
		if exists {
			// We'll be updating this existing advisory.
			advisory = &adv
		} else {
			return "", fmt.Errorf("advisory ID %q not found for package %q", reqID, request.Package)
		}
	} else {
		adv, exists := doc.Advisories.GetByAnyVulnerability(request.Aliases...)
		if exists {
			// We'll be updating this existing advisory.
			advisory = &adv
		} else {
			// We'll be creating a new advisory.
			newID, err := p.idGenerator.GenerateCGAID()
			if err != nil {
				return "", fmt.Errorf("generating CGA ID when creating new advisory: %w", err)
			}
			advisory = &v2.Advisory{
				ID: newID,
			}
		}
	}

	// Union the alias lists.
	updatedAliases := union(advisory.Aliases, request.Aliases)
	advisory.Aliases = updatedAliases

	if !request.Event.IsZero() {
		advisory.Events = append(advisory.Events, request.Event)
	}

	doc.Advisories = doc.Advisories.Upsert(advisory.ID, *advisory)

	// Write the updated document back to the file system

	var w rwfs.File
	if advisoryFileHadExisted {
		w, err = p.fsys.OpenAsWritable(advFileName)
		if err != nil {
			return "", fmt.Errorf("opening advisory file %q as writable: %w", advFileName, err)
		}
	} else {
		w, err = p.fsys.Create(advFileName)
		if err != nil {
			return "", fmt.Errorf("creating advisory file %q: %w", advFileName, err)
		}
	}

	if err := p.fsys.Truncate(advFileName, 0); err != nil {
		return "", fmt.Errorf("truncating advisory file %q (prior to writing to it): %w", advFileName, err)
	}

	if err := p.enc(w, *doc); err != nil {
		return "", fmt.Errorf("encoding advisory file %q with YAML: %w", advFileName, err)
	}

	if err := w.Close(); err != nil {
		return "", fmt.Errorf("closing advisory file %q: %w", advFileName, err)
	}

	return advisory.ID, nil
}

func union(slice1, slice2 []string) []string {
	m := make(map[string]struct{})
	for _, s := range slice1 {
		m[s] = struct{}{}
	}
	for _, s := range slice2 {
		m[s] = struct{}{}
	}
	result := make([]string, 0, len(m))
	for s := range m {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}
