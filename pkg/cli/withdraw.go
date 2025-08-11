package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/exp/slices"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/melange/pkg/sign"
	"github.com/chainguard-dev/clog"

	"github.com/spf13/cobra"
)

func cmdWithdraw() *cobra.Command {
	key := ""
	withdrawPackagesFile := ""
	cmd := &cobra.Command{
		Use:           "withdraw example-pkg-1.2.3-r4",
		Short:         "Withdraw packages from an APKINDEX.tar.gz",
		Example:       "withdraw --signing-key ./foo.rsa example-pkg-1.2.3-r4 also-bad-2.3.4-r1 <old/APKINDEX.tar.gz >new/APKINDEX.tar.gz",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			gone := make(map[string]bool)

			// Add packages from command line arguments
			for _, s := range args {
				gone[strings.TrimSuffix(s, ".apk")] = false
			}

			// Add packages from file if specified
			if withdrawPackagesFile != "" {
				filePackages, err := readPackagesFromFile(withdrawPackagesFile)
				if err != nil {
					return fmt.Errorf("reading packages file: %w", err)
				}
				for _, pkg := range filePackages {
					gone[strings.TrimSuffix(pkg, ".apk")] = false
				}
			}

			return withdraw(cmd.Context(), cmd.OutOrStdout(), cmd.InOrStdin(), key, gone)
		},
	}

	cmd.Flags().StringVar(&key, "signing-key", "melange.rsa", "the signing key to use")
	cmd.Flags().StringVar(&withdrawPackagesFile, "packages-file", "", "file containing list of packages to withdraw (one per line, supports comments with #)")

	return cmd
}

func withdraw(ctx context.Context, w io.Writer, r io.Reader, key string, gone map[string]bool) error {
	log := clog.FromContext(ctx)

	index, err := apk.IndexFromArchive(io.NopCloser(r))
	if err != nil {
		return fmt.Errorf("failed to read apkindex from archive file: %w", err)
	}

	index.Packages = slices.DeleteFunc(index.Packages, func(pkg *apk.Package) bool {
		pkgver := pkg.Name + "-" + pkg.Version
		_, ok := gone[pkgver]
		if ok {
			log.Infof("withdrawing %q", pkgver)
			gone[pkgver] = true
		}
		return ok
	})

	for pkg, ok := range gone {
		if !ok {
			log.Warnf("did not withdraw %q", pkg)
		}
	}

	archive, err := apk.ArchiveFromIndex(index)
	if err != nil {
		return fmt.Errorf("failed to create archive from index object: %w", err)
	}

	tmp, err := os.CreateTemp("", "wolifctl-withdraw")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}

	if _, err := io.Copy(tmp, archive); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	if err := sign.SignIndex(ctx, key, tmp.Name()); err != nil {
		return fmt.Errorf("signing index: %w", err)
	}

	signed, err := os.Open(tmp.Name())
	if err != nil {
		return fmt.Errorf("opening %s: %w", tmp.Name(), err)
	}

	if _, err := io.Copy(w, signed); err != nil {
		return fmt.Errorf("copying index: %w", err)
	}

	return nil
}

// readPackagesFromFile reads package names from a file, skipping blank lines and comments
func readPackagesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	var packages []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip blank lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		packages = append(packages, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	return packages, nil
}
