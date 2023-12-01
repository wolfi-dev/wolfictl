package dep

import (
	"fmt"
	"os"
	"path/filepath"
)

type Strategy interface {
	// Probe probes a path to determine if a strategy is applicable.
	Probe(path string) bool

	// LockFileName returns the name of the lockfile used by a language ecosystem, such as "go.mod".
	LockFileName() string

	// LocalLockFileName returns the name of the local lockfile used by a language ecosystem, such as "go.mod.local".
	LocalLockFileName() string

	// ChecksumFileName returns the name of the checksum file used by a language ecosystem, such as
	// "go.sum".  For languages which do not use a separate checksum file, returns an empty string.
	ChecksumFileName() string

	// LocalChecksumFileName returns the name of the local checksum file, such as "go.sum.local".
	LocalChecksumFileName() string

	// Rebase takes paths to two lockfiles and chooses the newest versions of every dependency possible, then outputs
	// a new file to outputPath.
	Rebase(pathA, pathB, outputPath string) error

	// UpdateChecksums updates a checksum file according to the dependencies listed in the input lockfile,
	// then outputs a new file to outputPath.
	UpdateChecksums(lockFile, outputFile string) error
}

// GetStrategy takes a path to checked out source code and returns a Strategy to modify the dependency
// data or an error.
func GetStrategy(path string) (Strategy, error) {
	strategies := []Strategy{
		GoStrategy{},
	}

	for _, strategy := range strategies {
		if strategy.Probe(path) {
			return strategy, nil
		}
	}

	return nil, fmt.Errorf("no dependency management strategy found for the given path")
}

// Rebase takes two paths and then rebases the lockfile as appropriate.  It uses atomic rename
// to update the final dependency file (pathB).
func Rebase(path string) error {
	strategy, err := GetStrategy(path)
	if err != nil {
		return err
	}

	upstreamFile := filepath.Join(path, strategy.LockFileName())
	downstreamFile := filepath.Join(path, strategy.LocalLockFileName())
	newFile := downstreamFile + ".new"

	if err := strategy.Rebase(upstreamFile, downstreamFile, newFile); err != nil {
		return fmt.Errorf("while rebasing: %w", err)
	}

	if err := os.Rename(newFile, downstreamFile); err != nil {
		return fmt.Errorf("while renaming the rebased file: %w", err)
	}

	return nil
}

// UpdateChecksums takes a path to checked out source code and updates the local checksum file.
func UpdateChecksums(path string) error {
	strategy, err := GetStrategy(path)
	if err != nil {
		return err
	}

	downstreamFile := filepath.Join(path, strategy.LocalLockFileName())
	downstreamChecksumFile := filepath.Join(path, strategy.LocalChecksumFileName())
	newChecksumFile := downstreamChecksumFile + ".new"

	if err := strategy.UpdateChecksums(downstreamFile, newChecksumFile); err != nil {
		return fmt.Errorf("while updating checksums: %w", err)
	}

	if err := os.Rename(newChecksumFile, downstreamChecksumFile); err != nil {
		return fmt.Errorf("while renaming the rebased file: %w", err)
	}

	return nil
}
