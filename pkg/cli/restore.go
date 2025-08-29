package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
)

type BulkRestoreRequest struct {
	APKs []string `json:"apks"`
}

type BulkRestoreResponse struct {
	RestoredAPKs   []string        `json:"restored_apks"`
	FailedRestores []FailedRestore `json:"failed_restores"`
}

type FailedRestore struct {
	Name         string `json:"name"`
	ErrorMessage string `json:"error_message"`
}

func cmdRestore() *cobra.Command {
	var arch string
	var packagesFile string

	cmd := &cobra.Command{
		Use:           "restore [packages...]",
		Short:         "Restore withdrawn packages in apk.cgr.dev",
		Example:       "restore example-pkg-1.2.3-r4 another-pkg-2.0.0-r1",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			log := clog.FromContext(ctx)

			var packages []string

			packages = append(packages, args...)
			if packagesFile != "" {
				filePackages, err := readPackagesFromFile(packagesFile)
				if err != nil {
					return fmt.Errorf("reading packages file: %w", err)
				}
				packages = append(packages, filePackages...)
			}

			if len(packages) == 0 {
				return fmt.Errorf("no packages specified")
			}

			// Validate package format
			for _, pkg := range packages {
				if !isValidPackageFormat(pkg) {
					return fmt.Errorf("invalid package format: %s (expected format: package-name-version, e.g., example-pkg-1.2.3-r4)", pkg)
				}
			}

			// Determine architectures to process, default means both
			var architectures []string
			if arch == "" {
				architectures = []string{"x86_64", "aarch64"}
			} else {
				architectures = []string{arch}
			}

			// Process each architecture
			for _, targetArch := range architectures {
				log.Infof("Processing architecture: %s", targetArch)
				if err := restorePackages(ctx, targetArch, packages); err != nil {
					return fmt.Errorf("failed to restore packages for %s: %w", targetArch, err)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&arch, "arch", "", "architecture to restore packages for (x86_64 or aarch64, defaults to both if not specified)")
	cmd.Flags().StringVar(&packagesFile, "packages-file", "", "file containing list of packages to restore (one per line, supports comments with #)")

	return cmd
}

func restorePackages(ctx context.Context, arch string, packages []string) error {
	// Get authentication token from environment
	authToken := os.Getenv("HTTP_AUTH")
	if authToken == "" {
		return fmt.Errorf("HTTP_AUTH environment variable is required")
	}

	if len(packages) == 1 {
		// Single package: use PATCH request
		url := fmt.Sprintf("https://apk.cgr.dev/chainguard/%s/%s", arch, packages[0])
		return makePatchRequest(ctx, url, authToken)
	} else {
		// Multiple packages: use POST request (bulk restore)
		url := fmt.Sprintf("https://apk.cgr.dev/chainguard/%s/restore", arch)
		return makePostRequest(ctx, url, authToken, packages)
	}
}

func makePatchRequest(ctx context.Context, url, authToken string) error {
	log := clog.FromContext(ctx)

	req, err := http.NewRequestWithContext(ctx, "PATCH", url, nil)
	if err != nil {
		return fmt.Errorf("creating PATCH request: %w", err)
	}

	req.SetBasicAuth("user", authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("making PATCH request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PATCH request failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.Infof("Successfully restored package via PATCH")
	return nil
}

func makePostRequest(ctx context.Context, url, authToken string, packages []string) error {
	log := clog.FromContext(ctx)

	requestBody := BulkRestoreRequest{
		APKs: packages,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("marshaling request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("creating POST request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("user", authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("making POST request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse and display response
	var response BulkRestoreResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("unmarshaling response: %w", err)
	}

	log.Infof("Restore operation completed:")
	log.Infof("Successfully restored: %v", response.RestoredAPKs)
	if len(response.FailedRestores) > 0 {
		for _, failed := range response.FailedRestores {
			log.Warnf("Failed to restore package %s: %s", failed.Name, failed.ErrorMessage)
		}
	}

	return nil
}

// isValidPackageFormat checks if the package name follows the expected format: package-name-version
// where version typically ends with -r<number>
func isValidPackageFormat(pkg string) bool {
	// Basic validation: should contain at least one hyphen and end with something like -r<number>
	parts := strings.Split(pkg, "-")
	if len(parts) < 3 {
		return false
	}

	// Check if the last part looks like a revision (starts with 'r' followed by numbers)
	lastPart := parts[len(parts)-1]
	if len(lastPart) < 2 || lastPart[0] != 'r' {
		return false
	}

	for i := 1; i < len(lastPart); i++ {
		if lastPart[i] < '0' || lastPart[i] > '9' {
			return false
		}
	}

	return true
}
