package yam

import (
	"fmt"
	"os"
	"path/filepath"

	osAdapter "github.com/chainguard-dev/yam/pkg/rwfs/os"
	"github.com/chainguard-dev/yam/pkg/yam"
	"github.com/chainguard-dev/yam/pkg/yam/formatted"
)

func FormatConfigurationFile(dir, filename string) error {
	yamConfig, err := os.Open(filepath.Join(dir, ".yam.yaml"))
	if err != nil {
		return fmt.Errorf("failed to open yam config file: %v", err)
	}
	defer yamConfig.Close()

	encodeOptions, err := formatted.ReadConfigFrom(yamConfig)
	if err != nil {
		return fmt.Errorf("failed to read yam config file: %v", err)
	}

	fsys := osAdapter.DirFS(dir)
	// Format file following the repo level format
	err = yam.Format(fsys, []string{filename}, yam.FormatOptions{EncodeOptions: *encodeOptions})
	if err != nil {
		return fmt.Errorf("error formatting the file %s: %v", filename, err)
	}
	return nil
}
