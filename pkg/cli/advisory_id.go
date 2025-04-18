package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	cgaid "github.com/chainguard-dev/advisory-schema/pkg/advisory"
)

func cmdAdvisoryID() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "id",
		Short:         "Generate a new advisory ID",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			id, err := cgaid.GenerateCGAID()
			if err != nil {
				return fmt.Errorf("generating advisory ID: %w", err)
			}

			fmt.Println(id)
			return nil
		},
	}

	return cmd
}
