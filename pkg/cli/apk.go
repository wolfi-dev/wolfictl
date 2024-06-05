package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"chainguard.dev/apko/pkg/apk/apk"
	"cloud.google.com/go/storage"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"
)

func cmdApk() *cobra.Command {
	cmd := &cobra.Command{Use: "apk"}
	cmd.AddCommand(cmdCp())
	cmd.AddCommand(cmdApkLs())
	return cmd
}

func cmdCp() *cobra.Command {
	var latest bool
	var indexURL, outDir, gcsPath string
	cmd := &cobra.Command{
		Use:          "cp",
		Aliases:      []string{"copy"},
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			errg, ctx := errgroup.WithContext(cmd.Context())

			repoURL := strings.TrimSuffix(indexURL, "/APKINDEX.tar.gz")

			index, arch, err := fetchAPKIndex(ctx, indexURL)
			if err != nil {
				return err
			}

			wantSet := map[string]struct{}{}
			for _, p := range args {
				wantSet[p] = struct{}{}
			}
			var packages []*apk.Package
			for _, pkg := range index.Packages {
				if _, ok := wantSet[pkg.Name]; !ok {
					continue
				}
				packages = append(packages, pkg)
			}

			if latest {
				packages = onlyLatest(packages)
			}

			if len(packages) == 0 {
				return fmt.Errorf("no packages found")
			}

			log.Printf("downloading %d packages for %s", len(packages), arch)

			for _, pkg := range packages {
				pkg := pkg
				errg.Go(func() error {
					fn := filepath.Join(outDir, arch, pkg.Filename())
					if _, err := os.Stat(fn); err == nil {
						log.Printf("skipping %s: already exists", fn)
						return nil
					}

					var rc io.ReadCloser
					if gcsPath == "" {
						u, err := url.Parse(fmt.Sprintf("%s/%s", repoURL, pkg.Filename()))
						if err != nil {
							return err
						}
						log.Println("downloading", u.Redacted())
						req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
						if err != nil {
							return err
						}
						addAuth(req)
						resp, err := http.DefaultClient.Do(req)
						if err != nil {
							return err
						}
						defer resp.Body.Close()

						if err := os.MkdirAll(filepath.Join(outDir, arch), 0o755); err != nil {
							return err
						}
						rc = resp.Body
					} else {
						gcsPath = strings.TrimPrefix(gcsPath, "gs://")
						bucket, path, _ := strings.Cut(gcsPath, "/")
						fullPath := filepath.Join(path, arch, pkg.Filename())
						log.Printf("downloading gs://%s/%s", bucket, fullPath)

						client, err := storage.NewClient(ctx)
						if err != nil {
							return err
						}
						rc, err = client.Bucket(bucket).Object(fullPath).NewReader(ctx)
						if err != nil {
							return err
						}
						defer rc.Close()
					}

					if err := os.MkdirAll(filepath.Dir(fn), 0o755); err != nil {
						return err
					}
					f, err := os.Create(fn)
					if err != nil {
						return err
					}
					defer f.Close()
					if _, err := io.Copy(f, rc); err != nil {
						return err
					}
					log.Printf("wrote %s", fn)
					return nil
				})

				// TODO: Also get (latest) runtime deps here?
			}

			if err := errg.Wait(); err != nil {
				return err
			}

			// Update the local index for all the apks currently in the outDir.
			index.Packages = nil

			if err := filepath.WalkDir(filepath.Join(outDir, arch), func(path string, _ fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !strings.HasSuffix(path, ".apk") {
					return nil
				}

				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()

				stat, err := f.Stat()
				if err != nil {
					return err
				}
				pkg, err := apk.ParsePackage(ctx, f, uint64(stat.Size()))
				if err != nil {
					return err
				}
				index.Packages = append(index.Packages, pkg)
				return nil
			}); err != nil {
				return err
			}
			fn := filepath.Join(outDir, arch, "APKINDEX.tar.gz")
			log.Printf("writing index: %s (%d total packages)", fn, len(index.Packages))
			f, err := os.Create(fn)
			if err != nil {
				return err
			}
			defer f.Close()
			r, err := apk.ArchiveFromIndex(index)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, r); err != nil {
				return err
			}

			// TODO: Sign index?

			return nil
		},
	}
	cmd.Flags().StringVarP(&outDir, "out-dir", "o", "./packages", "directory to copy packages to")
	cmd.Flags().StringVarP(&indexURL, "index", "i", "https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz", "APKINDEX.tar.gz URL")
	cmd.Flags().BoolVar(&latest, "latest", true, "copy only the latest version of each package")
	cmd.Flags().StringVar(&gcsPath, "gcs", "", "copy objects from a GCS bucket")
	return cmd
}

func cmdApkLs() *cobra.Command {
	var full bool
	var latest bool
	var j bool
	var packageFilter string

	cmd := &cobra.Command{
		Use:     "ls",
		Example: `wolfictl apk ls https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			u := args[0]

			dir := strings.TrimSuffix(u, "/APKINDEX.tar.gz")

			index, _, err := fetchAPKIndex(ctx, u)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			enc := json.NewEncoder(w)

			packages := index.Packages

			// TODO: origin filter as well?
			if packageFilter != "" {
				packages = slices.DeleteFunc(packages, func(pkg *apk.Package) bool {
					return pkg.Name != packageFilter
				})
			}

			if latest {
				packages = onlyLatest(packages)
			}

			for _, pkg := range packages {
				p := fmt.Sprintf("%s-%s.apk", pkg.Name, pkg.Version)
				u := fmt.Sprintf("%s/%s", dir, p)
				switch {
				case j:
					if err := enc.Encode(pkg); err != nil {
						return fmt.Errorf("encoding %s: %w", pkg.Name, err)
					}
				case full:
					fmt.Fprintf(w, "%s\n", u)
				default:
					fmt.Fprintf(w, "%s\n", p)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&packageFilter, "package", "P", "", "print only packages with the given name")
	cmd.Flags().BoolVar(&latest, "latest", false, "print only the latest version of each package")
	cmd.Flags().BoolVar(&full, "full", false, "print the full url or path")
	cmd.Flags().BoolVar(&j, "json", false, "print each package as json")

	return cmd
}

func fetchAPKIndex(ctx context.Context, indexURL string) (*apk.APKIndex, string, error) {
	var arch string
	repoURL := strings.TrimSuffix(indexURL, "/APKINDEX.tar.gz")
	var in io.ReadCloser
	switch {
	case indexURL == "-":
		in = os.Stdin
		arch = "x86_64" // TODO: This is hardcoded.
	case strings.HasPrefix(indexURL, "file://"):
		f, err := os.Open(strings.TrimPrefix(indexURL, "file://"))
		if err != nil {
			return nil, "", fmt.Errorf("opening %q: %w", indexURL, err)
		}
		in = f

		arch = repoURL[strings.LastIndex(repoURL, "/")+1:]
	default:
		u, err := url.Parse(indexURL)
		if err != nil {
			return nil, "", fmt.Errorf("parsing %q: %w", indexURL, err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, "", fmt.Errorf("GET %q: %w", u.Redacted(), err)
		}
		addAuth(req)
		resp, err := http.DefaultClient.Do(req) //nolint:bodyclose
		if err != nil {
			return nil, "", fmt.Errorf("GET %q: %w", u.Redacted(), err)
		}
		if resp.StatusCode >= 400 {
			return nil, "", fmt.Errorf("GET %q: status %d: %s", u.Redacted(), resp.StatusCode, resp.Status)
		}
		in = resp.Body

		arch = repoURL[strings.LastIndex(repoURL, "/")+1:]
	}
	defer in.Close()
	index, err := apk.IndexFromArchive(in)
	if err != nil {
		return nil, "", fmt.Errorf("parsing %q: %w", indexURL, err)
	}
	return index, arch, nil
}

func addAuth(req *http.Request) {
	env := os.Getenv("HTTP_AUTH")
	parts := strings.Split(env, ":")
	if len(parts) != 4 || parts[0] != "basic" {
		return
	}
	if req.URL.Host == parts[1] {
		req.SetBasicAuth(parts[2], parts[3])
	}
}

func onlyLatest(packages []*apk.Package) []*apk.Package {
	// by package
	highest := map[string]*apk.Package{}

	for _, pkg := range packages {
		got, err := apk.ParseVersion(pkg.Version)
		if err != nil {
			// TODO: We should really fail here.
			log.Printf("parsing %q: %v", pkg.Filename(), err)
			continue
		}

		have, ok := highest[pkg.Name]
		if !ok {
			highest[pkg.Name] = pkg
			continue
		}

		// TODO: We re-parse this for no reason.
		parsed, err := apk.ParseVersion(have.Version)
		if err != nil {
			// TODO: We should really fail here.
			log.Printf("parsing %q: %v", have.Version, err)
			continue
		}

		if apk.CompareVersions(got, parsed) > 0 {
			highest[pkg.Name] = pkg
		}
	}

	return maps.Values(highest)
}
