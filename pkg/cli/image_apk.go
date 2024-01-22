package cli

import (
	"fmt"
	"path"
	"slices"

	"chainguard.dev/melange/pkg/config"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func cmdImageAPK() *cobra.Command {
	p := &imageAPKParams{}
	cmd := &cobra.Command{
		Use:   "apk <image>",
		Short: "Show APK(s) in a container image",
		Example: `
  # Show all APKs in an image
  wolfictl image apk cgr.dev/chainguard/bash

  # Show all APKs in an image that own a component (based on a Syft analysis)
  wolfictl image apk cgr.dev/chainguard/coredns -c 'github.com/aws/aws-sdk-go'

  # Show all APKs in an image that own a component, and show the path to the
  # Melange configuration file for each APK, within the given directory
  wolfictl image apk cgr.dev/chainguard/prometheus-operator -c 'github.com/aws/aws-sdk-go' -d ~/code/wolfi-os
`,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			imageRef := args[0]

			imgSource, err := source.NewFromStereoscopeImage(source.StereoscopeImageConfig{
				Reference: imageRef,
				From:      image.OciRegistrySource,
			})
			if err != nil {
				return fmt.Errorf("unable to construct scan source for image %q: %w", imageRef, err)
			}
			defer imgSource.Close()

			cfg := syft.DefaultCreateSBOMConfig()
			imgSBOM, err := syft.CreateSBOM(cmd.Context(), imgSource, cfg)
			if err != nil {
				return fmt.Errorf("unable to create SBOM: %w", err)
			}

			distroID := imgSBOM.Artifacts.LinuxDistribution.ID
			if !slices.Contains([]string{"wolfi", "chainguard"}, distroID) {
				return fmt.Errorf("unsupported distro: %s", distroID)
			}

			r := &syftResults{sbom: imgSBOM}

			var apks []pkg.Package

			if c := p.component; c != "" {
				apks, err = r.apksOwningPackageWithName(c)
				if err != nil {
					return fmt.Errorf("unable to find APK package owning a component %q: %w", c, err)
				}
			} else {
				apks = r.apks()
			}

			if len(p.distroDirPaths) == 0 {
				for i := range apks {
					apk := apks[i]
					fmt.Println(apk.Name)
				}

				return nil
			}

			configPaths, err := apkConfigPaths(apks, p.distroDirPaths)
			if err != nil {
				return fmt.Errorf("unable to find configuration files for APK packages: %w", err)
			}

			for _, p := range configPaths {
				fmt.Println(p)
			}

			return nil
		},
	}

	p.addFlags(cmd)
	return cmd
}

type imageAPKParams struct {
	component      string
	distroDirPaths []string
}

func (p *imageAPKParams) addFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&p.component, "component", "c", "", "show only APKs containing the given component")
	cmd.Flags().StringSliceVarP(&p.distroDirPaths, "distro-dir", "d", nil, "path to a directory containing Melange build configuration files")
}

type syftResults struct {
	sbom                                *sbom.SBOM
	packageOwnershipsByOwnedPackageName map[string][]ownership
}

type ownership struct {
	owner pkg.Package
	owned pkg.Package
}

func (r *syftResults) apks() []pkg.Package {
	var apks []pkg.Package

	pkgs := r.sbom.Artifacts.Packages.Sorted(pkg.ApkPkg)
	for i := range pkgs {
		p := pkgs[i]
		// Skip findings from SBOMs
		if p.FoundBy == "sbom-cataloger" {
			continue
		}

		apks = append(apks, p)
	}

	return apks
}

func (r *syftResults) apksOwningPackageWithName(name string) ([]pkg.Package, error) {
	// Lazily create the index of owned package (by name) to APK package
	if r.packageOwnershipsByOwnedPackageName == nil {
		err := r.indexPackageOwnerships()
		if err != nil {
			return nil, fmt.Errorf("unable to index APK package ownerships: %w", err)
		}
	}

	// Lookup the APK package that owns the given package name
	ownerships, ok := r.packageOwnershipsByOwnedPackageName[name]
	if !ok || len(ownerships) == 0 {
		return nil, fmt.Errorf("no APK package owns %q", name)
	}

	var apks []pkg.Package
	for i := range ownerships {
		o := ownerships[i]
		apks = append(apks, o.owner)
	}

	return apks, nil
}

func (r *syftResults) indexPackageOwnerships() error {
	index := make(map[string][]ownership)

	for _, rel := range r.sbom.Relationships {
		if rel.Type != artifact.OwnershipByFileOverlapRelationship {
			continue
		}

		apkPkgID := rel.From.ID()
		ownedPkgID := rel.To.ID()

		apkPkg := r.sbom.Artifacts.Packages.Package(apkPkgID)
		if apkPkg == nil {
			return fmt.Errorf("unable to find owner package %q", apkPkgID)
		}
		if apkPkg.Type != pkg.ApkPkg {
			return fmt.Errorf(
				"expected APK package as owner in relatioship, got %s (for package %q)",
				apkPkg.Type,
				apkPkg.Name,
			)
		}

		ownedPkg := r.sbom.Artifacts.Packages.Package(ownedPkgID)
		if ownedPkg == nil {
			return fmt.Errorf("unable to find owned package %q", ownedPkgID)
		}

		o := ownership{
			owner: *apkPkg,
			owned: *ownedPkg,
		}

		index[ownedPkg.Name] = append(index[ownedPkg.Name], o)
	}

	r.packageOwnershipsByOwnedPackageName = index
	return nil
}

func apkConfigPaths(apks []pkg.Package, distroDirPaths []string) ([]string, error) {
	configIndexes := make([]*configs.Index[config.Configuration], 0, len(distroDirPaths))
	indexRootPaths := make([]string, 0, len(distroDirPaths))

	for _, p := range distroDirPaths {
		index, err := build.NewIndex(rwos.DirFS(p))
		if err != nil {
			return nil, fmt.Errorf("unable to index configuration files from %q: %w", p, err)
		}
		configIndexes = append(configIndexes, index)
		indexRootPaths = append(indexRootPaths, p)
	}

	configPaths := make([]string, 0, len(apks))

	for i := range apks {
		apk := apks[i]
		pathFound := false

		var origin string
		if m, ok := apk.Metadata.(pkg.ApkDBEntry); ok {
			origin = m.OriginPackage
		} else {
			origin = apk.Name
		}

		for i, index := range configIndexes {
			if p := index.Path(origin); p != "" {
				pathFound = true
				fullPath := path.Join(indexRootPaths[i], p)
				configPaths = append(configPaths, fullPath)
			}
		}

		if !pathFound {
			return nil, fmt.Errorf("unable to find configuration file for APK package %q", apk.Name)
		}
	}

	slices.Sort(configPaths)
	uniqueConfigPaths := slices.Compact(configPaths)

	return uniqueConfigPaths, nil
}
