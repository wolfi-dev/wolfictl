package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/dag"
)

func cmdText() *cobra.Command {
	var dir, pipelineDir, arch, t string
	var extraKeys, extraRepos []string
	text := &cobra.Command{
		Use:   "text",
		Short: "Print a sorted list of downstream dependent packages",
		Long: `This command prints a list of packages, sorted in the order they would need to be built.

If this command is successful, it means there is a solveable dependency graph and the packages can be built in the order they are printed.

If this fails, there may be an unsatisfiable dependency or a cycle in the graph.`,
		Args:   cobra.NoArgs,
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if pipelineDir == "" {
				pipelineDir = filepath.Join(dir, "pipelines")
			}

			arch := types.ParseArchitecture(arch).ToAPK()

			pkgs, err := dag.NewPackages(ctx, os.DirFS(dir), dir, pipelineDir)
			if err != nil {
				return fmt.Errorf("constructing new package set from directory %q: %w", dir, err)
			}
			g, err := dag.NewGraph(ctx, pkgs,
				dag.WithKeys(extraKeys...),
				dag.WithRepos(extraRepos...),
				dag.WithArch(arch))
			if err != nil {
				return fmt.Errorf("creating graph: %w", err)
			}

			return text(g, pkgs, arch, textType(t), os.Stdout)
		},
	}
	text.Flags().StringVarP(&dir, "dir", "d", ".", "directory to search for melange configs")
	text.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	text.Flags().StringVarP(&arch, "arch", "a", "x86_64", "architecture to build for")
	text.Flags().StringVarP(&t, "type", "t", string(typeTarget), fmt.Sprintf("What type of text to emit; values can be one of: %v", textTypes))
	text.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}, "path to extra keys to include in the build environment keyring")
	text.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{"https://packages.wolfi.dev/os"}, "path to extra repositories to include in the build environment")
	return text
}

type textType string

const (
	typeTarget                textType = "target"
	typeMakefileLine          textType = "makefile"
	typePackageName           textType = "name"
	typePackageVersion        textType = "version"
	typePackageNameAndVersion textType = "name-version"
)

var textTypes = []textType{
	typeTarget,
	typeMakefileLine,
	typePackageName,
	typePackageVersion,
	typePackageNameAndVersion,
}

func text(g *dag.Graph, pkgs *dag.Packages, arch string, t textType, w io.Writer) error {
	filtered, err := g.Filter(dag.FilterLocal())
	if err != nil {
		return err
	}

	all, err := filtered.ReverseSorted()
	if err != nil {
		return err
	}

	// Check that we emit the same set of packages as filtering only main packages.
	gmain, err := filtered.Filter(dag.OnlyMainPackages(pkgs))
	if err != nil {
		return err
	}
	mains, err := gmain.ReverseSorted()
	if err != nil {
		return err
	}
	want := make(map[string]struct{}, len(mains))
	for _, main := range mains {
		name := main.Name()
		want[name] = struct{}{}
	}

	got := make(map[string]struct{}, len(want))

	for _, node := range all {
		name := node.Name()
		pkg := pkgs.PkgInfo(name)

		if pkg == nil {
			// Expected for subpackages.
			continue
		}

		switch t {
		case typeTarget:
			fmt.Fprintf(w, "%s\n", makeTarget(name, arch, pkg))
		case typeMakefileLine:
			fmt.Fprintf(w, "%s\n", makefileEntry(name, pkg))
		case typePackageName:
			fmt.Fprintf(w, "%s\n", pkg.Name)
		case typePackageVersion:
			fmt.Fprintf(w, "%s\n", pkg.Version)
		case typePackageNameAndVersion:
			fmt.Fprintf(w, "%s-%s-r%d\n", pkg.Name, pkg.Version, pkg.Epoch)
		default:
			return fmt.Errorf("invalid type: %s", t)
		}

		if _, ok := want[name]; !ok {
			return fmt.Errorf("found unexpected package %q", name)
		}

		if _, ok := got[name]; ok {
			return fmt.Errorf("found duplicate package %q", name)
		}

		got[name] = struct{}{}
	}

	// Make sure we didn't miss anything somehow.
	for _, main := range mains {
		name := main.Name()
		if _, ok := got[name]; !ok {
			return fmt.Errorf("missing package %q", name)
		}
	}

	return nil
}

func makefileEntry(pkgName string, p *config.Package) string {
	return fmt.Sprintf("$(eval $(call build-package,%s,%s-%d))", pkgName, p.Version, p.Epoch)
}

func makeTarget(pkgName, arch string, p *config.Package) string {
	// note: using pkgName here because it may be a subpackage, not the main package declared within the config (i.e. `p.Name`)
	return fmt.Sprintf("make packages/%s/%s-%s-r%d.apk", arch, pkgName, p.Version, p.Epoch)
}
