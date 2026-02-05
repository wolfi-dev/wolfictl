package cli

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"sort"

	"github.com/chainguard-dev/yam/pkg/yam/formatted"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	adv2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"

	cgaid "github.com/chainguard-dev/advisory-schema/pkg/advisory"
)

func cmdAdvisoryMigrateIDs() *cobra.Command {
	p := &migrateIDsParams{}
	cmd := &cobra.Command{
		Use:           "migrate-ids",
		Short:         "Migrate advisory files to CGA IDs",
		Args:          cobra.NoArgs,
		Hidden:        true,
		SilenceErrors: true,
		Deprecated:    advisoryDeprecationMessage,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if p.advisoriesRepoDir == "" {
				if p.doNotDetectDistro {
					return fmt.Errorf("no advisories repo dir specified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("no advisories repo dir specified, and distro auto-detection failed: %w", err)
				}

				p.advisoriesRepoDir = d.Local.AdvisoriesRepo.Dir
				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			yamConfigFile, err := os.Open(".yam.yaml")
			if err != nil {
				return fmt.Errorf("unable to get yam configuration: %w", err)
			}
			yamConfig, err := formatted.ReadConfigFrom(yamConfigFile)
			if err != nil {
				return fmt.Errorf("unable to read yam configuration: %w", err)
			}

			advisoryFsys := rwos.DirFS(p.advisoriesRepoDir)
			index, err := adv2.NewIndex(cmd.Context(), advisoryFsys)
			if err != nil {
				return fmt.Errorf("unable to index advisory configs for directory %q: %w", p.advisoriesRepoDir, err)
			}

			IDs := []string{}
			for _, document := range index.Select().Configurations() {
				for _, adv := range document.Advisories {
					oldID := adv.ID
					adv.Aliases = append(adv.Aliases, adv.ID)
					sort.Strings(adv.Aliases)

					var err error
					adv.ID, err = cgaid.GenerateCGAID()
					if err != nil {
						return err
					}

					document.Advisories.Update(oldID, adv)

					IDs = append(IDs, adv.ID)
				}

				node := new(yaml.Node)
				err = node.Encode(document)
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

				err = advisoryFsys.Truncate(index.Path(document.Name()), 0)
				if err != nil {
					return err
				}

				f, err := advisoryFsys.OpenAsWritable(index.Path(document.Name()))
				if err != nil {
					return err
				}
				_, err = io.Copy(f, buf)
				if err != nil {
					return err
				}
			}

			checkUniqueIDs := make(map[string]bool)
			for _, item := range IDs {
				if _, value := checkUniqueIDs[item]; !value {
					checkUniqueIDs[item] = true
				} else {
					log.Fatal("Should not have any duplicate IDs")
				}
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type migrateIDsParams struct {
	doNotDetectDistro bool
	advisoriesRepoDir string
}

func (p *migrateIDsParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)

	cmd.Flags().StringVarP(&p.advisoriesRepoDir, "advisory-repo-dir", "a", "", "directory containing an advisory repository")
}
