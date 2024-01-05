package build

import (
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
)

func NewPackageSectionUpdater(
	updater configs.SectionUpdater[config.Package, config.Configuration],
) configs.EntryUpdater[config.Configuration] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[config.Package, config.Configuration](
		"package",
		updater,
		func(cfg config.Configuration, data config.Package) config.Configuration {
			cfg.Package = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[config.Configuration](yamlASTMutater)
}

func NewEnvironmentSectionUpdater(
	updater configs.SectionUpdater[types.ImageConfiguration, config.Configuration],
) configs.EntryUpdater[config.Configuration] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[types.ImageConfiguration, config.Configuration](
		"environment",
		updater,
		func(cfg config.Configuration, data types.ImageConfiguration) config.Configuration {
			cfg.Environment = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[config.Configuration](yamlASTMutater)
}

func NewPipelineSectionUpdater(
	updater configs.SectionUpdater[[]config.Pipeline, config.Configuration],
) configs.EntryUpdater[config.Configuration] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[[]config.Pipeline, config.Configuration](
		"pipeline",
		updater,
		func(cfg config.Configuration, data []config.Pipeline) config.Configuration {
			cfg.Pipeline = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[config.Configuration](yamlASTMutater)
}

func NewSubpackagesSectionUpdater(
	updater configs.SectionUpdater[[]config.Subpackage, config.Configuration],
) configs.EntryUpdater[config.Configuration] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[[]config.Subpackage, config.Configuration](
		"subpackages",
		updater,
		func(cfg config.Configuration, data []config.Subpackage) config.Configuration {
			cfg.Subpackages = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[config.Configuration](yamlASTMutater)
}
