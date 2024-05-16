package v2

import (
	"errors"
	"fmt"
	"io"

	"github.com/hashicorp/go-version"
	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/internal/errorhelpers"
	"gopkg.in/yaml.v3"
)

// SchemaVersion is the latest known schema version for advisory documents.
// Wolfictl can only operate on documents that use a schema version that is
// equal to or earlier than this version and that is not earlier than this
// version's MAJOR number.
const SchemaVersion = "2.0.2"

type Document struct {
	SchemaVersion string     `yaml:"schema-version"`
	Package       Package    `yaml:"package"`
	Advisories    Advisories `yaml:"advisories,omitempty"`
}

func (doc Document) Name() string {
	return doc.Package.Name
}

func (doc Document) Validate() error {
	return errorhelpers.LabelError(doc.Name(),
		errors.Join(
			doc.ValidateSchemaVersion(),
			doc.Package.Validate(),
			doc.Advisories.Validate(),
		),
	)
}

func (doc Document) ValidateSchemaVersion() error {
	docSchemaVersion, err := version.NewVersion(doc.SchemaVersion)
	if err != nil {
		return err
	}

	currentSchemaVersion, err := version.NewVersion(SchemaVersion)
	if err != nil {
		return err
	}

	if docSchemaVersion.GreaterThan(currentSchemaVersion) {
		return fmt.Errorf("document schema version %q is newer than the latest known schema version %q; if %q is supported by a later version of wolfictl, please update wolfictl and try this again", doc.SchemaVersion, SchemaVersion, doc.SchemaVersion)
	}

	// Document schema version also can't be earlier than the current schema version's MAJOR number.
	currentMajorNumber := currentSchemaVersion.Segments()[0]
	docMajorNumber := docSchemaVersion.Segments()[0]
	if docMajorNumber < currentMajorNumber {
		return fmt.Errorf("document schema version %q is too old to operate on with this version of wolfictl, document must use at least schema version \"%d\"", doc.SchemaVersion, currentMajorNumber)
	}

	return nil
}

func decodeDocument(r io.Reader) (*Document, error) {
	doc := &Document{}
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	err := decoder.Decode(doc)
	if err != nil {
		return nil, err
	}

	if doc.SchemaVersion == "" {
		doc.SchemaVersion = "1"
	}

	return doc, nil
}

type Package struct {
	Name string `yaml:"name"`
}

func (p Package) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("package name must not be empty")
	}

	return nil
}

type Advisories []Advisory

func (advs Advisories) Validate() error {
	if len(advs) == 0 {
		return fmt.Errorf("this file should not exist if there are no advisories recorded")
	}

	seenIDs := make(map[string]bool)
	var duplicateErrs []error
	for _, adv := range advs {
		if _, ok := seenIDs[adv.ID]; ok {
			duplicateErrs = append(duplicateErrs, fmt.Errorf("%s: %w", adv.ID, ErrAdvisoryIDDuplicated))
		}
		seenIDs[adv.ID] = true

		for _, alias := range adv.Aliases {
			if _, ok := seenIDs[alias]; ok {
				duplicateErrs = append(duplicateErrs, fmt.Errorf("%s: %w", alias, ErrAdvisoryAliasDuplicated))
			}
			seenIDs[alias] = true
		}
	}

	if len(duplicateErrs) > 0 {
		return errorhelpers.LabelError("advisories", errors.Join(duplicateErrs...))
	}

	return errorhelpers.LabelError("advisories",
		errors.Join(lo.Map(advs, func(adv Advisory, _ int) error {
			return adv.Validate()
		})...),
	)
}

var (
	ErrAdvisoryIDDuplicated    = errors.New("advisory ID is not unique")
	ErrAdvisoryAliasDuplicated = errors.New("advisory alias is not unique")
)

// Get returns the advisory with the given ID. If such an advisory does not
// exist, the second return value will be false; otherwise it will be true.
func (advs Advisories) Get(id string, aliases []string) (Advisory, bool) {
	for _, adv := range advs {
		if adv.ID == id {
			return adv, true
		}
	}

	for _, reqAlias := range aliases {
		for _, adv := range advs {
			for _, alias := range adv.Aliases {
				if alias == reqAlias {
					return adv, true
				}
			}
		}
	}

	return Advisory{}, false
}

// Get returns the advisory with the given ID. If such an advisory does not
// exist, the second return value will be false; otherwise it will be true.
func (advs Advisories) GetAlias(id string) (Advisory, bool) {
	for _, adv := range advs {
		for _, alias := range adv.Aliases {
			if alias == id {
				return adv, true
			}
		}
	}

	return Advisory{}, false
}

// GetByVulnerability returns the advisory that references the given
// vulnerability ID as its advisory ID or as one of the advisory's aliases. If
// such an advisory does not exist, the second return value will be false;
// otherwise it will be true.
func (advs Advisories) GetByVulnerability(id string) (Advisory, bool) {
	for _, adv := range advs {
		if adv.ID == id {
			return adv, true
		}

		for _, alias := range adv.Aliases {
			if alias == id {
				return adv, true
			}
		}
	}

	return Advisory{}, false
}

func (advs Advisories) Update(id string, advisory Advisory) Advisories {
	for i, adv := range advs {
		if adv.ID == id {
			advs[i] = advisory
			return advs
		}
	}

	for i, adv := range advs {
		for _, alias := range adv.Aliases {
			if alias == id {
				advs[i] = advisory
				return advs
			}
		}
	}

	return advs
}

// Implement sort.Interface for Advisories.

func (advs Advisories) Len() int {
	return len(advs)
}

func (advs Advisories) Less(i, j int) bool {
	return advs[i].ID < advs[j].ID
}

func (advs Advisories) Swap(i, j int) {
	advs[i], advs[j] = advs[j], advs[i]
}

func validateNotEmpty(s string) error {
	if s == "" {
		return fmt.Errorf("must not be empty")
	}

	return nil
}
