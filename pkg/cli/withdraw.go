package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/go-apk/pkg/apk"
	sign "github.com/chainguard-dev/go-apk/pkg/signature"

	"github.com/spf13/cobra"
)

func cmdWithdraw() *cobra.Command {
	key := ""
	cmd := &cobra.Command{
		Use:           "withdraw example-pkg-1.2.3-r4",
		Short:         "Withdraw packages from an APKINDEX.tar.gz",
		Example:       "withdraw --signing-key ./foo.rsa example-pkg-1.2.3-r4 also-bad-2.3.4-r1 <old/APKINDEX.tar.gz >new/APKINDEX.tar.gz",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			gone := make(map[string]bool, len(args))
			for _, s := range args {
				gone[strings.TrimSuffix(s, ".apk")] = false
			}

			return withdraw(cmd.Context(), cmd.OutOrStdout(), cmd.InOrStdin(), key, gone)
		},
	}

	cmd.Flags().StringVar(&key, "signing-key", "melange.rsa", "the signing key to use")

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
