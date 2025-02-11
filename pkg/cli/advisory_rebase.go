package cli

import (
	"fmt"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func cmdAdvisoryRebase() *cobra.Command {
	p := &rebaseParams{}
	cmd := &cobra.Command{
		Use:   "rebase <source-advisories-file-path> <destination-advisories-directory>",
		Short: "Apply a package’s latest advisory events to advisory data in another directory",
		Long: `Apply a package’s latest advisory events to advisory data in another directory.

Especially useful when a package's build configuration moves from one
repository to another, and you want to ensure that the advisory data for the
package is updated with the latest events from the original repository. This
helps ensure that any meaningful analysis is carried over to the new repository.

By default this command will "rebase" all advisories from the source location
onto the corresponding advisories file in the destination directory. But it's
also possible to rebase one advisory at a time, by using the -V flag to specify
a vulnerability ID or advisory ID for one particular advisory.
`,
		Example: `
wolfictl adv rebase ./argo-cd-2.8.yaml ../enterprise-advisories

wolfictl adv rebase ./argo-cd-2.8.yaml ../enterprise-advisories -V CVE-2021-25743
`,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			log := clog.FromContext(ctx)

			srcFile, dstDir := args[0], args[1]

			srcDir := filepath.Dir(srcFile)
			srcFsys := rwos.DirFS(srcDir)

			log = log.With("srcDir", srcDir, "dstDir", dstDir)
			log.Debug("creating index for source directory")
			srcIndex, err := v2.NewIndex(ctx, srcFsys)
			if err != nil {
				return fmt.Errorf("creating advisory index for source directory %q: %w", srcDir, err)
			}

			dstFsys := rwos.DirFS(dstDir)
			log.Debug("creating index for destination directory")
			dstIndex, err := v2.NewIndex(ctx, dstFsys)
			if err != nil {
				return fmt.Errorf("creating advisory index for destination directory %q: %w", dstDir, err)
			}

			log.Debugf("confirming package name for source file input %q", srcFile)
			srcFilePath, err := filepath.Rel(srcDir, srcFile)
			if err != nil {
				return fmt.Errorf("finding source document %q within source index: %w", srcFilePath, err)
			}
			srcDoc, err := srcIndex.Select().WhereFilePath(srcFilePath).First()
			if err != nil {
				return fmt.Errorf("finding source document for %q: %w", srcFilePath, err)
			}
			packageName := srcDoc.Configuration().Package.Name

			opts := advisory.RebaseOptions{
				SourceIndex:      srcIndex,
				DestinationIndex: dstIndex,
				PackageName:      packageName,
				VulnerabilityID:  p.vuln,
				CurrentTime:      v2.Now(),
			}

			log.Debug("attempting rebase")

			if err := advisory.Rebase(clog.WithLogger(ctx, log), opts); err != nil {
				return fmt.Errorf("rebasing advisories: %w", err)
			}

			log.Info("rebased advisories successfully")

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type rebaseParams struct {
	vuln string
}

func (p *rebaseParams) addFlagsTo(cmd *cobra.Command) {
	addVulnFlag(&p.vuln, cmd)
}
