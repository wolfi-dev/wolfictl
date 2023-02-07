package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gitlab.alpinelinux.org/alpine/go/repository"
)

var repos = map[string]string{
	"wolfi":  "https://packages.wolfi.dev/os",
	"stage1": "https://packages.wolfi.dev/bootstrap/stage1",
	"stage2": "https://packages.wolfi.dev/bootstrap/stage2",
	"stage3": "https://packages.wolfi.dev/bootstrap/stage3",
}

func Apk() *cobra.Command {
	var arch, repo string
	cmd := &cobra.Command{
		Use:  "apk",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !strings.HasSuffix(args[0], ".apk") {
				args[0] += ".apk"
			}

			// Map a friendly string like "wolfi" to its repo URL.
			if got, found := repos[repo]; found {
				repo = got
			}

			url := fmt.Sprintf("%s/%s/%s", repo, arch, args[0])
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
	cmd.Flags().StringVar(&repo, "repo", "wolfi", "repo to get packages from")
	return cmd
}

func Index() *cobra.Command {
	var arch, repo string
	cmd := &cobra.Command{
		Use:  "index",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Map a friendly string like "wolfi" to its repo URL.
			if got, found := repos[repo]; found {
				repo = got
			}

			url := fmt.Sprintf("%s/%s/APKINDEX.tar.gz", repo, arch)
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
	cmd.Flags().StringVar(&repo, "repo", "wolfi", "repo to get packages from")
	return cmd
}
