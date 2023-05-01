package build

import (
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
)

func NewAdvisoriesSectionUpdater(
	updater configs.SectionUpdater[build.Advisories, build.Configuration],
) configs.EntryUpdater[build.Configuration] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[build.Advisories, build.Configuration](
		"advisories",
		updater,
		func(cfg build.Configuration, data build.Advisories) build.Configuration {
			cfg.Advisories = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[build.Configuration](yamlASTMutater)
}

func NewSecfixesSectionUpdater(
	updater configs.SectionUpdater[build.Secfixes, build.Configuration],
) configs.EntryUpdater[build.Configuration] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[build.Secfixes, build.Configuration](
		"secfixes",
		updater,
		func(cfg build.Configuration, data build.Secfixes) build.Configuration {
			cfg.Secfixes = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[build.Configuration](yamlASTMutater)
}

func NewPackageSectionUpdater(
	updater configs.SectionUpdater[build.Package, build.Configuration],
) configs.EntryUpdater[build.Configuration] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[build.Package, build.Configuration](
		"package",
		updater,
		func(cfg build.Configuration, data build.Package) build.Configuration {
			cfg.Package = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[build.Configuration](yamlASTMutater)
}

func NewEnvironmentSectionUpdater(
	updater configs.SectionUpdater[types.ImageConfiguration, build.Configuration],
) configs.EntryUpdater[build.Configuration] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[types.ImageConfiguration, build.Configuration](
		"package",
		updater,
		func(cfg build.Configuration, data types.ImageConfiguration) build.Configuration {
			cfg.Environment = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[build.Configuration](yamlASTMutater)
}

func NewPipelineSectionUpdater(
	updater configs.SectionUpdater[[]build.Pipeline, build.Configuration],
) configs.EntryUpdater[build.Configuration] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[[]build.Pipeline, build.Configuration](
		"package",
		updater,
		func(cfg build.Configuration, data []build.Pipeline) build.Configuration {
			cfg.Pipeline = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[build.Configuration](yamlASTMutater)
}

func NewSubpackagesSectionUpdater(
	updater configs.SectionUpdater[[]build.Subpackage, build.Configuration],
) configs.EntryUpdater[build.Configuration] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[[]build.Subpackage, build.Configuration](
		"package",
		updater,
		func(cfg build.Configuration, data []build.Subpackage) build.Configuration {
			cfg.Subpackages = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[build.Configuration](yamlASTMutater)
}
