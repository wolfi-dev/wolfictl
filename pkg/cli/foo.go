package cli

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"github.com/wolfi-dev/wupdater/pkg/foo"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

type options struct {
	outDir                 string
	baseURIFormat          string
	additionalRepositories []string
	additionalKeyrings     []string
}

func ApkBuild() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:     "apkbuild",
		Short:   "Converts an APKBUILD package into a mconvert.yaml",
		Long:    `Converts an APKBUILD package into a mconvert.yaml.`,
		Example: `  mconvert convert apkbuild libx11`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			if len(args) != 1 {
				return errors.New("too many arguments, expected only 1")
			}

			return o.ApkBuildCmd(cmd.Context(), args[0])
		},
	}

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	cmd.Flags().StringVar(&o.outDir, "out-dir", filepath.Join(cwd, "generated"), "directory where mconvert config will be output")
	cmd.Flags().StringVar(&o.baseURIFormat, "base-uri-format", "https://git.alpinelinux.org/aports/plain/main/%s/APKBUILD", "URI to use for querying APKBUILD for provided package name")
	cmd.Flags().StringArrayVar(&o.additionalRepositories, "additional-repositories", []string{}, "additional repositories to be added to mconvert environment config")
	cmd.Flags().StringArrayVar(&o.additionalKeyrings, "additional-keyrings", []string{}, "additional repositories to be added to mconvert environment config")

	return cmd
}

func (o options) ApkBuildCmd(ctx context.Context, packageName string) error {
	context, err := foo.New()
	if err != nil {
		return errors.Wrap(err, "initialising convert command")
	}

	context.OutDir = o.outDir

	configFilename := fmt.Sprintf(o.baseURIFormat, packageName)

	context.Logger.Printf("generating mconvert config files for APKBUILD %s", configFilename)

	//err = context.Generate(configFilename, packageName)
	//if err != nil {
	//	return errors.Wrap(err, "generating mconvert configuration")
	//}

	return nil
}
