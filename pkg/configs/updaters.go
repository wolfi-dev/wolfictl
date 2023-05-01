package configs

import (
	"errors"

	"gopkg.in/yaml.v3"
)

// An EntryUpdater is a function that takes a configuration Entry and modifies a
// specific section of the configuration (type T) data. It's meant to be passed
// into NewTargetedYAMLASTMutater as an argument to update the YAML data that
// underlies the configuration data.
//
// The EntryUpdater ultimately needs to be passed to an Index to do the actual
// update operation.
type EntryUpdater[T Configuration] func(*Index[T], Entry[T]) error

// ErrSkip is a special sentinel error that signals that the given entry should
// be skipped during batch processing. When a caller's function returns ErrSkip,
// the error is not returned back to the caller.
var ErrSkip = errors.New("skipping operation for this entry")

// A SectionUpdater is a function that takes a Configuration (type T) and
// returns an updated version of a section (type K) of that Configuration.
type SectionUpdater[K any, T Configuration] func(configuration T) (K, error)

// NewTargetedYAMLASTMutater returns a YAMLASTMutater designed to update a
// single "section" of the YAML AST. The section is root-level mapping key, the
// data of which is described by type K.
func NewTargetedYAMLASTMutater[K any, T Configuration](
	sectionName string,
	updater SectionUpdater[K, T],
	cfgSectionDataAssigner func(configuration T, sectionData K) T,
) YAMLASTMutater[T] {
	return func(cfg T, node *yaml.Node) error {
		sectionNode := yamlNodeForKey(node, sectionName)

		sectionData := new(K)
		err := sectionNode.Decode(sectionData)
		if err != nil {
			return err
		}
		cfg = cfgSectionDataAssigner(cfg, *sectionData)

		updatedSectionData, err := updater(cfg)
		if err != nil {
			return err
		}

		err = sectionNode.Encode(updatedSectionData)
		if err != nil {
			return err
		}

		return nil
	}
}
