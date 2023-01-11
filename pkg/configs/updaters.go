package configs

import (
	"errors"
	"fmt"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"gopkg.in/yaml.v3"
)

type updateFunc func(Entry) error

// ErrSkip is a special sentinel error that signals that the given entry should
// be skipped during batch processing. When a caller's function returns ErrSkip,
// the error is not returned back to the caller.
var ErrSkip = errors.New("skipping operation for this entry")

type UpdaterFunc[T any] func(configuration build.Configuration) (T, error)

// UpdateAdvisories applies the given updater function to modify the "advisories"
// section of each configuration in the selection.
func (s Selection) UpdateAdvisories(updater UpdaterFunc[build.Advisories]) error {
	u := s.index.newAdvisoriesUpdater(updater)
	for _, e := range s.entries {
		err := s.index.update(e, u)
		if err != nil {
			if errors.Is(err, ErrSkip) {
				continue
			}

			return fmt.Errorf("unable to update advisories for %q: %w", e.Path(), err)
		}
	}

	return nil
}

func (i *Index) newAdvisoriesUpdater(updater UpdaterFunc[build.Advisories]) updateFunc {
	yamlUpdateFunc := newYAMLSectionUpdateFunc(
		"advisories",
		updater,
		func(cfg build.Configuration, data build.Advisories) build.Configuration {
			cfg.Advisories = data
			return cfg
		},
	)

	return i.newYAMLUpdateFunc(yamlUpdateFunc)
}

// UpdateSecfixes applies the given updater function to modify the "secfixes"
// section of each configuration in the selection.
func (s Selection) UpdateSecfixes(updater UpdaterFunc[build.Secfixes]) error {
	u := s.index.newSecfixesUpdater(updater)
	for _, e := range s.entries {
		err := s.index.update(e, u)
		if err != nil {
			if errors.Is(err, ErrSkip) {
				continue
			}

			return fmt.Errorf("unable to update secfixes for %q: %w", e.Path(), err)
		}
	}

	return nil
}

func (i *Index) newSecfixesUpdater(updater UpdaterFunc[build.Secfixes]) updateFunc {
	yamlUpdateFunc := newYAMLSectionUpdateFunc(
		"secfixes",
		updater,
		func(cfg build.Configuration, data build.Secfixes) build.Configuration {
			cfg.Secfixes = data
			return cfg
		},
	)

	return i.newYAMLUpdateFunc(yamlUpdateFunc)
}

// UpdatePackage applies the given updater function to modify the "package"
// section of each configuration in the selection.
func (s Selection) UpdatePackage(updater UpdaterFunc[build.Package]) error {
	u := s.index.newPackageUpdater(updater)
	for _, e := range s.entries {
		err := s.index.update(e, u)
		if err != nil {
			if errors.Is(err, ErrSkip) {
				continue
			}

			return fmt.Errorf("unable to update package for %q: %w", e.Path(), err)
		}
	}

	return nil
}

func (i *Index) newPackageUpdater(updater UpdaterFunc[build.Package]) updateFunc {
	yamlUpdateFunc := newYAMLSectionUpdateFunc(
		"package",
		updater,
		func(cfg build.Configuration, data build.Package) build.Configuration {
			cfg.Package = data
			return cfg
		},
	)

	return i.newYAMLUpdateFunc(yamlUpdateFunc)
}

// UpdateEnvironment applies the given updater function to modify the "environment"
// section of each configuration in the selection.
func (s Selection) UpdateEnvironment(updater UpdaterFunc[types.ImageConfiguration]) error {
	u := s.index.newEnvironmentUpdater(updater)
	for _, e := range s.entries {
		err := s.index.update(e, u)
		if err != nil {
			if errors.Is(err, ErrSkip) {
				continue
			}

			return fmt.Errorf("unable to update environment for %q: %w", e.Path(), err)
		}
	}

	return nil
}

func (i *Index) newEnvironmentUpdater(updater UpdaterFunc[types.ImageConfiguration]) updateFunc {
	yamlUpdateFunc := newYAMLSectionUpdateFunc(
		"environment",
		updater,
		func(cfg build.Configuration, data types.ImageConfiguration) build.Configuration {
			cfg.Environment = data
			return cfg
		},
	)

	return i.newYAMLUpdateFunc(yamlUpdateFunc)
}

// UpdatePipeline applies the given updater function to modify the "pipeline"
// section of each configuration in the selection.
func (s Selection) UpdatePipeline(updater UpdaterFunc[[]build.Pipeline]) error {
	u := s.index.newPipelineUpdater(updater)
	for _, e := range s.entries {
		err := s.index.update(e, u)
		if err != nil {
			if errors.Is(err, ErrSkip) {
				continue
			}

			return fmt.Errorf("unable to update pipeline for %q: %w", e.Path(), err)
		}
	}

	return nil
}

func (i *Index) newPipelineUpdater(updater UpdaterFunc[[]build.Pipeline]) updateFunc {
	yamlUpdateFunc := newYAMLSectionUpdateFunc(
		"pipeline",
		updater,
		func(cfg build.Configuration, data []build.Pipeline) build.Configuration {
			cfg.Pipeline = data
			return cfg
		},
	)

	return i.newYAMLUpdateFunc(yamlUpdateFunc)
}

// UpdateSubpackages applies the given updater function to modify the "subpackages"
// section of each configuration in the selection.
func (s Selection) UpdateSubpackages(updater UpdaterFunc[[]build.Subpackage]) error {
	u := s.index.newSubpackagesUpdater(updater)
	for _, e := range s.entries {
		err := s.index.update(e, u)
		if err != nil {
			if errors.Is(err, ErrSkip) {
				continue
			}

			return fmt.Errorf("unable to update subpackages for %q: %w", e.Path(), err)
		}
	}

	return nil
}

func (i *Index) newSubpackagesUpdater(updater UpdaterFunc[[]build.Subpackage]) updateFunc {
	yamlUpdateFunc := newYAMLSectionUpdateFunc(
		"subpackages",
		updater,
		func(cfg build.Configuration, data []build.Subpackage) build.Configuration {
			cfg.Subpackages = data
			return cfg
		},
	)

	return i.newYAMLUpdateFunc(yamlUpdateFunc)
}

func newYAMLSectionUpdateFunc[T any](
	sectionName string,
	updater UpdaterFunc[T],
	cfgSectionDataAssigner func(configuration build.Configuration, sectionData T) build.Configuration,
) yamlUpdater {
	return func(cfg build.Configuration, node *yaml.Node) error {
		sectionNode := yamlNodeForKey(node, sectionName)

		sectionData := new(T)
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
