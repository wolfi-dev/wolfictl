//go:build integration
// +build integration

package scan

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
	"github.com/wolfi-dev/wolfictl/pkg/sbom"
)

var (
	updateGoldenFiles = flag.Bool("update-golden-files", false, "update golden files")
)

var testDBArchivePath = filepath.Join("testdata", "grypedb", "grypedb.tar.gz")

func getGrypeDB() (string, error) {
	fi, err := os.Stat(testDBArchivePath)
	if err == nil && fi.Size() > 0 {
		return testDBArchivePath, nil
	}

	// Note: We've pinned to a specific build of the Grype DB for reproducibility.
	//
	// Every several months or so, we should consider whether we want to update the
	// pinned version. It's not strictly necessary, but it may help us catch more
	// kinds of issues with vulnerability matching. When we update the pinned
	// version we'll need to regenerate the golden files.
	const dbURL = "https://toolbox-data.anchore.io/grype/databases/vulnerability-db_v5_2024-06-11T01:29:53Z_1718079715.tar.gz"

	resp, err := http.Get(dbURL)
	if err != nil {
		return "", fmt.Errorf("downloading Grype DB archive: %w", err)
	}
	defer resp.Body.Close()

	dbArchive, err := os.Create(testDBArchivePath)
	if err != nil {
		return "", fmt.Errorf("creating local Grype DB archive file: %w", err)
	}

	_, err = io.Copy(dbArchive, resp.Body)
	if err != nil {
		return "", fmt.Errorf("writing Grype DB archive to local file: %w", err)
	}

	return testDBArchivePath, nil
}

func TestScanner_ScanAPK(t *testing.T) {
	localDBPath, err := getGrypeDB()
	if err != nil {
		t.Fatalf("getting Grype DB: %v", err)
	}

	testTargets := []sbom.TestTarget{
		"crane-0.14.0-r0.apk",
		"crane-0.19.1-r6.apk",
		"go-1.21-1.21.0-r0.apk",
		"openjdk-10-jre-10.0.2-r0.apk",
		"openjdk-21-21.0.3-r3.apk",
		"openssl-3.3.0-r0.apk",
		"openssl-3.3.0-r8.apk",
		"perl-yaml-syck-1.34-r3.apk",
		"powershell-7.4.1-r0.apk",
		"php-odbc-8.2.11-r1.apk",
		"py3-poetry-core-1.8.0-r0.apk",
		"py3-poetry-core-1.9.0-r1.apk",
		"python-3.11-3.11.1-r5.apk",
		"terraform-1.3.9-r0.apk",
		"terraform-1.5.7-r12.apk",
		"thanos-0.32-0.32.5-r4.apk",
	}
	const goldenFileSuffix = ".wolfictl-scan.json"

	scannerOpts := Options{
		PathOfDatabaseArchiveToImport:      localDBPath,
		PathOfDatabaseDestinationDirectory: filepath.Dir(localDBPath),
		DisableDatabaseAgeValidation:       true,
	}
	scanner, err := NewScanner(scannerOpts)
	if err != nil {
		t.Fatalf("creating new scanner: %v", err)
	}

	for _, tt := range testTargets {
		for _, arch := range []string{"x86_64", "aarch64"} {
			localPath := tt.LocalPath(arch)

			t.Run(tt.Describe(arch), func(t *testing.T) {
				err := tt.Download(arch)
				if err != nil {
					t.Fatalf("downloading APK: %v", err)
				}

				f, err := os.Open(localPath)
				if err != nil {
					t.Fatalf("opening local APK file for analysis: %v", err)
				}

				s, err := scanner.ScanAPK(context.Background(), f, "wolfi")
				if err != nil {
					t.Fatalf("scanning APK: %v", err)
				}

				actual := &bytes.Buffer{}
				enc := json.NewEncoder(actual)
				enc.SetIndent("", "  ")
				err = enc.Encode(s)
				if err != nil {
					t.Fatalf("encoding vulnerability scan results to JSON: %v", err)
				}

				goldenFilePath := tt.GoldenFilePath(arch, goldenFileSuffix)

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

					_, err = io.Copy(goldenfile, actual)
					if err != nil {
						t.Fatalf("writing new scan results to golden file: %v", err)
					}

					t.Logf("updated golden file: %s", goldenFilePath)
					return
				}

				goldenfile, err := os.Open(goldenFilePath)
				if err != nil {
					t.Fatalf("opening golden file: %v", err)
				}
				defer goldenfile.Close()

				expectedBytes, err := io.ReadAll(goldenfile)
				if err != nil {
					t.Fatalf("reading golden file: %v", err)
				}

				if diff := cli.Diff("expected", expectedBytes, "actual", actual.Bytes(), false); len(diff) > 0 {
					t.Errorf("unexpected vulnerability scan results (-want +got):\n%s", diff)
				}
			})
		}
	}
}
