package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/advisory/question"
	"github.com/wolfi-dev/wolfictl/pkg/question/graph"
)

func cmdAdvisoryGuideGraph() *cobra.Command {
	return &cobra.Command{
		Use:           "graph",
		Short:         "Generate a DOT graph of the advisory guide interview questions",
		Deprecated:    advisoryDeprecationMessage,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sampleReq := advisory.Request{
				Package:    "foo",
				AdvisoryID: "CGA-xxxx-xxxx-xxxx",
			}

			dot, err := graph.Dot(cmd.Context(), question.IsFalsePositive, sampleReq)
			if err != nil {
				return fmt.Errorf("generating DOT: %w", err)
			}

			fmt.Print(dot)

			return nil
		},
	}
}
