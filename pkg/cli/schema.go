package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"github.com/invopop/jsonschema"
	"github.com/spf13/cobra"
)

type schemaOpts struct {
	// File path to write output to
	OutFile string
}

type sourceType string

var (
	melangeSource sourceType = "melange"
	apkoSource    sourceType = "apko"
)

func Schema() *cobra.Command {
	o := &schemaOpts{}

	cmd := &cobra.Command{
		Use:   "schema",
		Short: "Generate json schema for melange/apko.",
		Example: `
	  wolfictl schema > melange.schema.json
	  `,
		SilenceErrors: true,
		Args:          cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.Cmd(cmd.Context(), sourceType(args[0]))
		},
	}
	return cmd
}

func (o schemaOpts) Cmd(ctx context.Context, source sourceType) error {
	r := new(jsonschema.Reflector)

	var s *jsonschema.Schema
	switch source {
	case melangeSource:
		r.AddGoComments("chainguard.dev/melange", "./")
		s = r.Reflect(&build.Configuration{})

	case apkoSource:
		r.AddGoComments("chainguard.dev/apko", "./")
		s = r.Reflect(&types.ImageConfiguration{})

	default:
		return fmt.Errorf("unknown schema source: %s", source)
	}

	// Match the format of those in: https://github.com/SchemaStore/schemastore/tree/master/src/schemas/json
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	w := os.Stdout
	if o.OutFile != "" {
		f, err := os.Create(o.OutFile)
		if err != nil {
			return fmt.Errorf("creating output file: %v", err)
		}
		w = f
	}

	_, err = fmt.Fprintf(w, "%s", data)
	return err
}
