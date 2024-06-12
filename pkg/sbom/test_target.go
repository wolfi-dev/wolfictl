package sbom

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// TestTarget represents an APK file that can be used as a test target for
// integration tests.
type TestTarget string

// LocalPath returns the local path to the APK file for the given test target
// for the given architecture. The path is relative to the current working
// directory.
func (tt TestTarget) LocalPath(arch string) string {
	return filepath.Join("testdata", "apks", arch, string(tt))
}

// Describe returns a human-readable description of the test target for the
// given architecture.
func (tt TestTarget) Describe(arch string) string {
	return fmt.Sprintf("%s (%s)", tt, arch)
}

// GoldenFilePath returns the local path to the golden file for the given test
// target. Any given suffix will be appended to the filename (e.g.
// ".syft.json").
func (tt TestTarget) GoldenFilePath(arch, suffix string) string {
	return filepath.Join("testdata", "goldenfiles", arch, string(tt)+suffix)
}

// APKRepoURL returns the web URL to the APK file for the given test target for
// the given architecture.
func (tt TestTarget) APKRepoURL(arch string) string {
	const testTargetRepoURL = "https://packages.wolfi.dev/os"
	return fmt.Sprintf("%s/%s/%s", testTargetRepoURL, arch, tt)
}

// Download fetches the APK file for the given test target for the given
// architecture and writes it to the local filesystem.
//
// If the file already exists, it is not re-downloaded.
func (tt TestTarget) Download(arch string) error {
	localPath := tt.LocalPath(arch)
	fi, err := os.Stat(localPath)
	if err == nil && fi.Size() > 0 {
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("checking for existing local APK file: %w", err)
	}

	err = os.MkdirAll(filepath.Dir(localPath), 0755)
	if err != nil {
		return fmt.Errorf("creating directory for local APK file: %w", err)
	}

	// if the file doesn't exist, we need to fetch it
	f, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("creating local APK file: %w", err)
	}
	defer f.Close()

	resp, err := http.Get(tt.APKRepoURL(arch))
	if err != nil {
		return fmt.Errorf("fetching APK: %w", err)
	}
	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return fmt.Errorf("writing fetched APK to local file: %w", err)
	}
	resp.Body.Close()

	return nil
}
