package advisory

import (
	"io"
	"io/fs"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
	"gopkg.in/yaml.v3"
)

func NewIndex(fsys rwfs.FS) (*configs.Index[Document], error) {
	return configs.NewIndex[Document](fsys, newConfigurationDecodeFunc(fsys))
}

func NewIndexFromPaths(fsys rwfs.FS, paths ...string) (*configs.Index[Document], error) {
	return configs.NewIndexFromPaths[Document](fsys, newConfigurationDecodeFunc(fsys), paths...)
}

func newConfigurationDecodeFunc(fsys fs.FS) func(string) (*Document, error) {
	return func(path string) (*Document, error) {
		file, err := fsys.Open(path)
		if err != nil {
			return nil, err
		}

		return DecodeDocument(file)
	}
}

func DecodeDocument(r io.Reader) (*Document, error) {
	doc := &Document{}
	err := yaml.NewDecoder(r).Decode(doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

type Document struct {
	Package Package `yaml:"package"`

	Secfixes Secfixes `yaml:"secfixes,omitempty"`

	Advisories Advisories `yaml:"advisories,omitempty"`
}

func (d Document) Name() string {
	return d.Package.Name
}

type Package struct {
	Name string `yaml:"name"`
}

type Secfixes map[string][]string

type Advisories map[string][]Entry

type Entry struct {
	Timestamp       time.Time         `yaml:"timestamp"`
	Status          vex.Status        `yaml:"status"`
	Justification   vex.Justification `yaml:"justification,omitempty"`
	ImpactStatement string            `yaml:"impact,omitempty"`
	ActionStatement string            `yaml:"action,omitempty"`
	FixedVersion    string            `yaml:"fixed-version,omitempty"`
}
