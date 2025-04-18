package v2

import (
	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
)

func NewSchemaVersionSectionUpdater(newSchemaVersion string) configs.EntryUpdater[v2.Document] {
	updater := func(_ v2.Document) (string, error) {
		return newSchemaVersion, nil
	}

	yamlASTMutater := configs.NewTargetedYAMLASTMutater(
		"schema-version",
		updater,
		func(doc v2.Document, data string) v2.Document {
			doc.SchemaVersion = data
			return doc
		},
	)

	return configs.NewYAMLUpdateFunc(yamlASTMutater)
}

func NewAdvisoriesSectionUpdater(
	updater configs.SectionUpdater[v2.Advisories, v2.Document],
) configs.EntryUpdater[v2.Document] {
	yamlASTMutater := configs.NewTargetedYAMLASTMutater(
		"advisories",
		updater,
		func(doc v2.Document, data v2.Advisories) v2.Document {
			doc.Advisories = data

			// Since we're using _this_ version of wolfictl to update the document, we
			// should update the schema version, which ensures that any features of the
			// current schema being used in this document update are accounted for in the
			// document's expressed schema version.
			doc.SchemaVersion = v2.SchemaVersion

			return doc
		},
	)

	return configs.NewYAMLUpdateFunc(yamlASTMutater)
}
