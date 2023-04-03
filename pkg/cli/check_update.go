package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"

	"github.com/wolfi-dev/wolfictl/pkg/lint"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/update"
)

func CheckUpdate() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:               "update",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Short:             "Check Wolfi update configs",
		RunE: func(cmd *cobra.Command, files []string) error {
			return checkUpdates(dir, files)
		},
	}

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	cmd.Flags().StringVarP(&dir, "directory", "d", cwd, "directory containing melange configs")

	return cmd
}

func checkUpdates(dir string, files []string) error {
	o := update.New()
	o.GithubReleaseQuery = true
	o.ReleaseMonitoringQuery = true
	o.ErrorMessages = make(map[string]string)
	checkErrors := make(lint.EvalRuleErrors, 0)

	packagesToUpdate := []string{}
	for _, f := range files {
		packagesToUpdate = append(packagesToUpdate, strings.TrimSuffix(f, ".yaml"))
	}
	newVersions, err := o.GetNewVersions(dir, packagesToUpdate)
	if err != nil {
		checkErrors = append(checkErrors, lint.EvalRuleError{
			Error: fmt.Errorf(err.Error()),
		})
	}

	for _, message := range o.ErrorMessages {
		checkErrors = append(checkErrors, lint.EvalRuleError{
			Error: errors.New(message),
		})
	}

	for k, v := range newVersions {
		checkErrors = append(checkErrors, lint.EvalRuleError{
			Error: fmt.Errorf("package %s: update found newer version %s compared with package.version in melange config", k, v.Version),
		})
	}

	return checkErrors.WrapErrors()
}
