package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/yam/pkg/yam"
	"github.com/chainguard-dev/yam/pkg/yam/formatted"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
)

func cmdLintYam() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "yam [file]...",
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, args []string) error {
			fsys := os.DirFS(".")
			paths := lo.Map(args, toCleanPath)

			encodeOptions, err := formatted.ReadConfig()
			if err != nil {
				return fmt.Errorf("unable to load yam config: %w", err)
			}

			formatOptions := yam.FormatOptions{
				EncodeOptions:          *encodeOptions,
				FinalNewline:           true,
				TrimTrailingWhitespace: true,
			}

			err = yam.Lint(fsys, paths, yam.ExecDiff, formatOptions)
			if err != nil {
				if errors.Is(err, yam.ErrDidNotPassLintCheck) {
					fmt.Println("\nYAML needs to be formatted. 👻")
					fmt.Println("Run `yam` to fix automatically. For more information, see https://github.com/chainguard-dev/yam")
					fmt.Println()
				}

				return err
			}

			fmt.Println("YAML is formatted correctly! 🎉")

			return nil
		},
	}

	return cmd
}

func toCleanPath(p string, _ int) string {
	return filepath.Clean(p)
}
