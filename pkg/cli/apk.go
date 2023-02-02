package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"gitlab.alpinelinux.org/alpine/go/repository"
)

func Apk() *cobra.Command {
	var arch string
	cmd := &cobra.Command{
		Use:  "apk",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			url := fmt.Sprintf("https://packages.wolfi.dev/os/%s/%s", arch, args[0])
			resp, err := http.Get(url) //nolint:gosec
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				return fmt.Errorf("GET %s (%d): %s", url, resp.StatusCode, b)
			}

			pkg, err := repository.ParsePackage(resp.Body)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(pkg)
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "x86_64", "arch of package to get")
	return cmd
}

func Index() *cobra.Command {
	var arch string
	cmd := &cobra.Command{
		Use:  "index",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			url := fmt.Sprintf("https://packages.wolfi.dev/os/%s/APKINDEX.tar.gz", arch)
			resp, err := http.Get(url) //nolint:gosec
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				return fmt.Errorf("GET %s (%d): %s", url, resp.StatusCode, b)
			}

			idx, err := repository.IndexFromArchive(resp.Body)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(idx)
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "x86_64", "arch of package to get")
	return cmd
}
