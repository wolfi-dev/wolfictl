package dep

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

type GoStrategy struct {
	Strategy
}

// Probe checks for a go.mod file and returns true if one is found,
// otherwise false.
func (s GoStrategy) Probe(path string) bool {
	targetFile := filepath.Join(path, s.LockFileName())

	_, err := os.Stat(targetFile)
	if err != nil {
		return false
	}

	return true
}

// LockFileName returns the name of the Go lockfile, "go.mod".
func (s GoStrategy) LockFileName() string {
	return "go.mod"
}

// LockFileName returns the name of the local Go lockfile, "go.mod.local".
func (s GoStrategy) LocalLockFileName() string {
	return "go.mod.local"
}

// ChecksumFileName returns the name of the Go checksum file, "go.sum".
func (s GoStrategy) ChecksumFileName() string {
	return "go.sum"
}

// LocalChecksumFileName returns the name of the local Go checksum file, "go.sum.local".
func (s GoStrategy) LocalChecksumFileName() string {
	return "go.sum.local"
}

func loadModFile(path string) (*modfile.File, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	return modfile.Parse(filepath.Base(path), content, nil)
}

// Rebase performs a rebase of the go.mod file.
// We do not process requires entries as it may point to a fork of the module
// which may not be compatible.
func (s GoStrategy) Rebase(upstreamFile, downstreamFile, outputFile string) error {
	upstreamModFile, err := loadModFile(upstreamFile)
	if err != nil {
		return fmt.Errorf("loading upstream go.mod file: %w", err)
	}

	downstreamModFile, err := loadModFile(downstreamFile)
	if err != nil {
		return fmt.Errorf("loading downstream go.mod file: %w", err)
	}

	newModFile := &modfile.File{Syntax: &modfile.FileSyntax{}}
	newModFile.AddGoStmt(upstreamModFile.Go.Version)
	newModFile.AddModuleStmt(upstreamModFile.Module.Mod.Path)

	if upstreamModFile.Toolchain != nil && upstreamModFile.Toolchain.Name != "" {
		newModFile.AddToolchainStmt(upstreamModFile.Toolchain.Name)
	}

	for _, downstreamPkg := range downstreamModFile.Require {
		for _, upstreamPkg := range upstreamModFile.Require {
			if upstreamPkg.Mod.Path == downstreamPkg.Mod.Path {
				var targetVersion string

				if semver.Compare(downstreamPkg.Mod.Version, upstreamPkg.Mod.Version) > 0 {
					targetVersion = downstreamPkg.Mod.Version
				} else {
					targetVersion = upstreamPkg.Mod.Version
				}

				newModFile.AddNewRequire(upstreamPkg.Mod.Path, targetVersion, upstreamPkg.Indirect)
			}
		}
	}

	newModFile.SetRequireSeparateIndirect(newModFile.Require)

	for _, upstreamPkg := range upstreamModFile.Exclude {
		newModFile.AddExclude(upstreamPkg.Mod.Path, upstreamPkg.Mod.Version)
	}

	for _, upstreamPkg := range upstreamModFile.Replace {
		newModFile.AddReplace(upstreamPkg.Old.Path, upstreamPkg.Old.Version, upstreamPkg.New.Path, upstreamPkg.New.Version)
	}

	for _, upstreamPkg := range upstreamModFile.Retract {
		newModFile.AddRetract(modfile.VersionInterval{Low: upstreamPkg.Low, High: upstreamPkg.High}, upstreamPkg.Rationale)
	}

	newModFile.Cleanup()

	payload, err := newModFile.Format()
	if err != nil {
		return fmt.Errorf("formatting rebased go.mod file: %w", err)
	}

	if err := os.WriteFile(outputFile, payload, 0o644); err != nil {
		return fmt.Errorf("writing rebased go.mod file: %w", err)
	}

	return nil
}
