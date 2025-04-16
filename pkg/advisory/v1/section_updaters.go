package v1

import (
	v1 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v1"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
)

func NewAdvisoriesSectionUpdater(
	updater configs.SectionUpdater[v1.Advisories, v1.Document],
) configs.EntryUpdater[v1.Document] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater(
		"advisories",
		updater,
		func(cfg v1.Document, data v1.Advisories) v1.Document {
			cfg.Advisories = data
			return cfg
		},
	)

	return configs.NewYAMLUpdateFunc(yamlASTMutater)
}
