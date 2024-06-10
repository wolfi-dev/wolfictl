//go:build integration
// +build integration

package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"chainguard.dev/melange/pkg/cli"
)

var (
	updateGoldenFiles = flag.Bool("update-golden-files", false, "update golden files")
)

// TestTargets is a list of APKs to use as test targets for generating SBOMs.
// This list can be re-used for integration tests of other logic that anzlyzes
// APKs.
var TestTargets = []TestTarget{
	"crane-0.19.1-r6.apk",

	// Note: Syft is producing nondeterministic results for these APKs, so the tests
	// aren't stable. Uncomment them when the issue is resolved.
	//
	// "jenkins-2.461-r0.apk",
	// "jruby-9.4-9.4.7.0-r0.apk",

	"openjdk-21-21.0.3-r3.apk",
	"openssl-3.3.0-r8.apk",
	"perl-yaml-syck-1.34-r3.apk",
	"powershell-7.4.1-r0.apk",
	"php-odbc-8.2.11-r1.apk",
	"py3-poetry-core-1.9.0-r1.apk",
	"terraform-1.5.7-r12.apk",
	"thanos-0.32-0.32.5-r4.apk",
}

// TestTarget represents an APK file that can be used as a test target for
// integration tests.
type TestTarget string

// LocalPath returns the local path to the APK file for the given test target
// for the given architecture. The path is relative to the current working
// directory, so provide a value for relativePrefix to navigate to the known
// location of the test data from the caller's working directory.
func (tt TestTarget) LocalPath(relativePrefix, arch string) string {
	if relativePrefix == "" {
		relativePrefix = "."
	}

	return filepath.Join(relativePrefix, "testdata", "apks", arch, string(tt))
}

// Describe returns a human-readable description of the test target for the
// given architecture.
func (tt TestTarget) Describe(arch string) string {
	return fmt.Sprintf("%s (%s)", tt, arch)
}

// GoldenFilePath returns the local path to the golden file for the given test
// target.
func (tt TestTarget) GoldenFilePath(relativePrefix, arch string) string {
	if relativePrefix == "" {
		relativePrefix = "."
	}
	return filepath.Join(relativePrefix, "testdata", "goldenfiles", arch, string(tt)+".syft.json")
}

// APKRepoURL returns the web URL to the APK file for the given test target for
// the given architecture.
func (tt TestTarget) APKRepoURL(arch string) string {
	const testTargetRepoURL = "https://packages.wolfi.dev/os"
	return fmt.Sprintf("%s/%s/%s", testTargetRepoURL, arch, tt)
}

// Download fetches the APK file for the given test target for the given
// architecture and writes it to the local filesystem using the given
// relativePrefix. If the file already exists, it is not re-downloaded.
func (tt TestTarget) Download(relativePrefix, arch string) error {
	localPath := tt.LocalPath(relativePrefix, arch)
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

	return nil
}

func TestGenerate(t *testing.T) {
	for _, tt := range TestTargets {
		for _, arch := range []string{"x86_64", "aarch64"} {
			localPath := tt.LocalPath("", arch)

			t.Run(tt.Describe(arch), func(t *testing.T) {
				err := tt.Download("", arch)
				if err != nil {
					t.Fatalf("downloading APK: %v", err)
				}

				f, err := os.Open(localPath)
				if err != nil {
					t.Fatalf("opening local APK file for analysis: %v", err)
				}

				s, err := Generate(context.Background(), localPath, f, "wolfi")
				if err != nil {
					t.Fatalf("generating SBOM: %v", err)
				}
				r, err := ToSyftJSON(s)
				if err != nil {
					t.Fatalf("encoding SBOM to Syft JSON: %v", err)
				}

				goldenFilePath := tt.GoldenFilePath("", arch)

				if *updateGoldenFiles {
					err := os.MkdirAll(filepath.Dir(goldenFilePath), 0755)
					if err != nil {
						t.Fatalf("creating directory for golden file: %v", err)
					}
					goldenfile, err := os.Create(goldenFilePath)
					if err != nil {
						t.Fatalf("creating golden file: %v", err)
					}
					defer goldenfile.Close()

					generated, err := io.ReadAll(r)
					if err != nil {
						t.Fatalf("reading generated SBOM for golden file: %v", err)
					}
					formatted := formatJSON(t, generated)
					_, err = goldenfile.Write(formatted)
					if err != nil {
						t.Fatalf("writing formatted SBOM to golden file: %v", err)
					}

					_, err = io.Copy(goldenfile, r)
					if err != nil {
						t.Fatalf("writing generated SBOM to golden file: %v", err)
					}

					t.Logf("updated golden file: %s", goldenFilePath)
					return
				}

				goldenfile, err := os.Open(goldenFilePath)
				if err != nil {
					t.Fatalf("opening golden file: %v", err)
				}

				expectedBytes, err := io.ReadAll(goldenfile)
				if err != nil {
					t.Fatalf("reading golden file: %v", err)
				}
				actualBytes, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("reading generated SBOM: %v", err)
				}

				if diff := cli.Diff("expected", expectedBytes, "actual", formatJSON(t, actualBytes), false); len(diff) > 0 {
					t.Errorf("unexpected SBOM generated (-want +got):\n%s", diff)
				}
			})
		}
	}
}

func formatJSON(t *testing.T, b []byte) []byte {
	t.Helper()

	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, b, "", "  "); err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}
	return prettyJSON.Bytes()
}
