package advisory

import (
	"github.com/wolfi-dev/wolfictl/pkg/configs"
)

func NewAdvisoriesSectionUpdater(
	updater configs.SectionUpdater[Advisories, Document],
) configs.EntryUpdater[Document] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[Advisories, Document](
		"advisories",
		updater,
		func(cfg Document, data Advisories) Document {
			cfg.Advisories = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[Document](yamlASTMutater)
}

func NewSecfixesSectionUpdater(
	updater configs.SectionUpdater[Secfixes, Document],
) configs.EntryUpdater[Document] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[Secfixes, Document](
		"secfixes",
		updater,
		func(cfg Document, data Secfixes) Document {
			cfg.Secfixes = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[Document](yamlASTMutater)
}
