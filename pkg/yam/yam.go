package yam

import (
	"fmt"
	"os"
	"path/filepath"

	osAdapter "github.com/chainguard-dev/yam/pkg/rwfs/os"
	"github.com/chainguard-dev/yam/pkg/util"
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

// TryReadingEncodeOptions does a "best effort" retrieval of the yam encode
// options. If no yam config is present in the given directory, no error is
// returned, and a set of default options are returned. An error is only
// returned if there is a problem reading the (present) yam config file.
func TryReadingEncodeOptions(dir string) (formatted.EncodeOptions, error) {
	defaultOpts := formatted.EncodeOptions{}

	yamCfgPath := filepath.Join(dir, util.ConfigFileName)
	yamCfgFile, err := os.Open(yamCfgPath)
	if err != nil {
		return defaultOpts, nil
	}

	readOpts, err := formatted.ReadConfigFrom(yamCfgFile)
	if err != nil {
		return defaultOpts, fmt.Errorf("reading yam config from %q: %w", yamCfgPath, err)
	}

	if err := yamCfgFile.Close(); err != nil {
		return defaultOpts, fmt.Errorf("closing yam config file: %w", err)
	}

	return *readOpts, nil
}
