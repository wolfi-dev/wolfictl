package advisory

import (
	"github.com/wolfi-dev/wolfictl/pkg/configs"
)

func NewAdvisoriesSectionUpdater(
	updater configs.SectionUpdater[[]Advisory, Document],
) configs.EntryUpdater[Document] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater[[]Advisory, Document](
		"advisories",
		updater,
		func(cfg Document, data []Advisory) Document {
			cfg.Advisories = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc[Document](yamlASTMutater)
}
