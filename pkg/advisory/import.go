package advisory

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	adv2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

// ImporAdvisoriesYAML import and yaml Advisories data and present as a config index struct
func ImporAdvisoriesYAML(inputData []byte) (tempDir string, documents *configs.Index[v2.Document], err error) {
	yamlDocs := bytes.Split(inputData, []byte("\n---\n"))
	// Unmarshal YAML documents
	var docs []v2.Document
	for _, doc := range yamlDocs {
		var pkg v2.Document
		err = yaml.Unmarshal(doc, &pkg)
		if err != nil {
			return "", nil, fmt.Errorf("unable to unmarshall input file: %v", err)
		}

		docs = append(docs, pkg)
	}

	tempDir, err = os.MkdirTemp("", "adv-")
	if err != nil {
		return "", nil, fmt.Errorf("unable to create temporary directory: %v", err)
	}
	for _, doc := range docs {
		f, err := os.Create(filepath.Join(tempDir, fmt.Sprintf("%s.advisories.yaml", doc.Name())))
		if err != nil {
			return "", nil, fmt.Errorf("failed to create adv file: %v", err)
		}

		d, err := yaml.Marshal(doc)
		if err != nil {
			return "", nil, fmt.Errorf("failed to marshal package %q: %v", doc.Package.Name, err)
		}
		_, err = f.Write(d)
		if err != nil {
			return "", nil, fmt.Errorf("failed save data to file: %v", err)
		}

		f.Close()
	}

	advisoryFsys := rwos.DirFS(tempDir)
	advisoryDocIndices, err := adv2.NewIndex(context.Background(), advisoryFsys)
	if err != nil {
		return "", nil, fmt.Errorf("unable to index advisory configs for directory %q: %v", tempDir, err)
	}

	return tempDir, advisoryDocIndices, nil
}
