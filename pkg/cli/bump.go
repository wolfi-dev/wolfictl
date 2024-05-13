package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"github.com/spf13/cobra"
)

const epochPattern = `epoch: %d`

type bumpOptions struct {
	repoDir string
	epoch   bool
	dryRun  bool
}

// this feels very hacky but the Makefile is going away with help from Dag so plan to delete this func soon
// for now wolfi is using a Makefile, if it exists check if the package is listed and update the version + epoch if it is
func updateMakefile(repoDir, packageName, latestVersion string, epoch uint64) error {
	file, err := os.Open(filepath.Join(repoDir, "Makefile"))
	if err != nil {
		// if the Makefile doesn't exist anymore let's just return
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var newFile []byte

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, fmt.Sprintf("$(eval $(call build-package,%s,", packageName)) {
			line = fmt.Sprintf("$(eval $(call build-package,%s,%s-r%d))", packageName, latestVersion, epoch)
		}
		newFile = append(newFile, []byte(line+"\n")...)
	}

	info, err := os.Stat(filepath.Join(repoDir, "Makefile"))
	if err != nil {
		return fmt.Errorf("failed to check file permissions of the Makefile: %w", err)
	}

	if err := os.WriteFile(filepath.Join(repoDir, "Makefile"), newFile, info.Mode()); err != nil {
		return fmt.Errorf("failed to write Makefile: %w", err)
	}

	return nil
}

func cmdBump() *cobra.Command {
	opts := bumpOptions{}
	cmd := &cobra.Command{
		Use:     "bump config[.yaml] [config[.yaml]...]",
		Short:   "Bumps the epoch field in melange configuration files",
		Example: "wolfictl bump openssh.yaml perl lib*.yaml",
		Long: `Bumps the epoch field in melange configuration files

The bump subcommand increments version numbers in package config files.
For now it will only bump epoch numbers but a future version will
allow users to control versions expressed in semver.

wolfictl bump can take a filename, a package or a file glob, increasing
the version in each matching configuration file:

    wolfictl bump zlib.yaml
    wolfictl bump openssl
    wolfictl bump lib*.yaml

The command assumes it is being run from the top of the wolfi/os
repository. To look for files in another location use the --repo flag.
You can use --dry-run to see which versions will be bumped without
modifying anything in the filesystem.

`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if len(args) == 0 {
				cmd.Help() //nolint:errcheck
				return fmt.Errorf("not enough arguments")
			}
			files := []string{}
			for _, fname := range args {
				_, err := os.Stat(filepath.Join(opts.repoDir, fname+".yaml"))
				if err == nil {
					files = append(files, filepath.Join(opts.repoDir, fname+".yaml"))
					continue
				}

				if !os.IsNotExist(err) {
					return fmt.Errorf("while checking config path %s: %w", fname, err)
				}

				m, err := filepath.Glob(filepath.Join(opts.repoDir, fname))
				if err == nil {
					files = append(files, m...)
					continue
				}
				return fmt.Errorf("unable to find config files from: %s", fname)
			}

			if opts.dryRun {
				fmt.Fprint(os.Stderr, "dry-run: not writing data\n")
			}

			for _, f := range files {
				if err := bumpEpoch(ctx, opts, f); err != nil {
					return err
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&opts.epoch, "epoch", true, "bump the package epoch")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "don't change anything, just print what would be done")
	cmd.Flags().StringVar(&opts.repoDir, "repo", ".", "path to the wolfi/os repository")

	return cmd
}

func bumpEpoch(ctx context.Context, opts bumpOptions, path string) error {
	cfg, err := config.ParseConfiguration(ctx, path)
	if err != nil {
		return fmt.Errorf("unable to parse configuration at %q: %w", path, err)
	}

	fmt.Fprintf(
		os.Stderr, "bumping %s-%s-%d in %s to epoch %d\n", cfg.Package.Name,
		cfg.Package.Version, cfg.Package.Epoch, path, cfg.Package.Epoch+1,
	)

	if opts.dryRun {
		return nil
	}

	original, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening config file: %w", err)
	}

	scanner := bufio.NewScanner(original)
	scanner.Split(bufio.ScanLines)
	newFile := []string{}
	found := false
	old := fmt.Sprintf(epochPattern, cfg.Package.Epoch)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == old {
			found = true
			newFile = append(
				newFile, strings.ReplaceAll(
					scanner.Text(), old, fmt.Sprintf(epochPattern, cfg.Package.Epoch+1),
				),
			)
		} else {
			newFile = append(newFile, scanner.Text())
		}
	}
	original.Close()

	if !found {
		return fmt.Errorf("unable to find epoch tag in yaml config")
	}

	if err := os.WriteFile(
		path, []byte(strings.Join(newFile, "\n")+"\n"), os.FileMode(0o644),
	); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	if err := updateMakefile(opts.repoDir, cfg.Package.Name, cfg.Package.Version, cfg.Package.Epoch+1); err != nil {
		return fmt.Errorf("updating makefile: %w", err)
	}

	return nil
}
