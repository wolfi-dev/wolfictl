package update

import "chainguard.dev/melange/pkg/build"

type MelageConfig struct {
	Package  build.Package    `yaml:"package"`
	Pipeline []build.Pipeline `yaml:"pipeline,omitempty"`
}
