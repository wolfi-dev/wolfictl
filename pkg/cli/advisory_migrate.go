package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/chainguard-dev/yam/pkg/yam/formatted"
	"github.com/spf13/cobra"
	v1 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v1"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"gopkg.in/yaml.v3"
)

func AdvisoryMigrate() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "migrate <path/to/advisories.yaml>",
		Short:         "Migrate advisory files to v2 schema from v1 schema",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			yamConfigFile, err := os.Open(".yam.yaml")
			if err != nil {
				return fmt.Errorf("unable to get yam configuration: %w", err)
			}
			yamConfig, err := formatted.ReadConfigFrom(yamConfigFile)
			if err != nil {
				return fmt.Errorf("unable to read yam configuration: %w", err)
			}

			if len(args) >= 1 {
				for _, arg := range args {
					f, err := os.Open(arg)
					if err != nil {
						return err
					}

					v1doc, err := v1.DecodeDocument(f)
					if err != nil {
						return fmt.Errorf("failed to decode v1 advisory document %q: %w", arg, err)
					}

					doc, err := v2.MigrateV1Document(v1doc)
					if err != nil {
						return err
					}

					node := new(yaml.Node)
					err = node.Encode(doc)
					if err != nil {
						return err
					}

					buf := new(bytes.Buffer)
					yamEncoder, err := formatted.NewEncoder(buf).UseOptions(*yamConfig)
					if err != nil {
						return err
					}

					err = yamEncoder.Encode(node)
					if err != nil {
						return err
					}

					err = os.Truncate(arg, 0)
					if err != nil {
						return err
					}
					_, err = io.Copy(f, buf)
					if err != nil {
						return err
					}
				}

				return nil
			}

			// Migrate all files in current directory

			advisoriesRepoDir := "."

			advisoriesFsys := rwos.DirFS(advisoriesRepoDir)
			v1Index, err := v1.NewIndex(advisoriesFsys)
			if err != nil {
				return err
			}

			for _, v1Document := range v1Index.Select().Configurations() {
				v1Document := v1Document

				doc, err := v2.MigrateV1Document(&v1Document)
				if err != nil {
					return fmt.Errorf("failed to decode v1 advisory document for package %q: %w", v1Document.Name(), err)
				}

				node := new(yaml.Node)
				err = node.Encode(doc)
				if err != nil {
					return err
				}

				buf := new(bytes.Buffer)
				yamEncoder, err := formatted.NewEncoder(buf).UseOptions(*yamConfig)
				if err != nil {
					return err
				}

				err = yamEncoder.Encode(node)
				if err != nil {
					return err
				}

				err = advisoriesFsys.Truncate(v1Index.Path(v1Document.Name()), 0)
				if err != nil {
					return err
				}

				f, err := advisoriesFsys.OpenAsWritable(v1Index.Path(v1Document.Name()))
				if err != nil {
					return err
				}
				_, err = io.Copy(f, buf)
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	return cmd
}
