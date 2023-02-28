package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"runtime"
	"sort"
	"strings"
	"sync"

	melange "chainguard.dev/melange/pkg/cli"
	"cloud.google.com/go/storage"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/index"
	"gitlab.alpinelinux.org/alpine/go/repository"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
)

var repos = map[string]string{
	"wolfi":  "https://packages.wolfi.dev/os",
	"stage1": "https://packages.wolfi.dev/bootstrap/stage1",
	"stage2": "https://packages.wolfi.dev/bootstrap/stage2",
	"stage3": "https://packages.wolfi.dev/bootstrap/stage3",
}

func Apk() *cobra.Command {
	var arch, repo string
	cmd := &cobra.Command{
		Use:  "apk",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Map a friendly string like "wolfi" to its repo URL.
			if got, found := repos[repo]; found {
				repo = got
			}

			if len(args) == 0 {
				// Get the index and present a searchable list to select.
				idx, err := index.Index(arch, repo)
				if err != nil {
					return err
				}

				var items []list.Item
				for _, p := range idx.Packages {
					items = append(items, item{p})
				}
				m := &model{list: list.New(items, list.NewDefaultDelegate(), 0, 0)}
				m.list.Title = "Select a Package"
				p := tea.NewProgram(m, tea.WithAltScreen())
				if _, err := p.Run(); err != nil {
					return err
				}

				it := m.list.SelectedItem()
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(it.(item).p)
			}

			if !strings.HasSuffix(args[0], ".apk") {
				args[0] += ".apk"
			}

			url := fmt.Sprintf("%s/%s/%s", repo, arch, args[0])
			resp, err := http.Get(url) //nolint:gosec
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				return fmt.Errorf("GET %s (%d): %s", url, resp.StatusCode, b)
			}

			pkg, err := repository.ParsePackage(resp.Body)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(pkg)
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "x86_64", "arch of package to get")
	cmd.Flags().StringVar(&repo, "repo", "wolfi", "repo to get packages from")
	return cmd
}

func Index() *cobra.Command {
	var arch, repo string
	cmd := &cobra.Command{
		Use:  "index",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Map a friendly string like "wolfi" to its repo URL.
			if got, found := repos[repo]; found {
				repo = got
			}

			idx, err := index.Index(arch, repo)
			if err != nil {
				return err
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(idx)
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "x86_64", "arch of package to get")
	cmd.Flags().StringVar(&repo, "repo", "wolfi", "repo to get packages from")
	return cmd
}

var docStyle = lipgloss.NewStyle().Margin(1, 2)

type item struct {
	p *repository.Package
}

func (i item) Title() string       { return i.p.Name }
func (i item) Description() string { return i.p.Version }
func (i item) FilterValue() string { return fmt.Sprintf("%s-%s", i.p.Name, i.p.Version) }

type model struct {
	list list.Model
}

func (m *model) Init() tea.Cmd { return nil }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter", "ctrl+c":
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		h, v := docStyle.GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m *model) View() string {
	return docStyle.Render(m.list.View())
}

var buckets = map[string]string{
	"wolfi":  "gs://wolfi-production-registry-destination/os",
	"stage1": "gs://wolfi-production-registry-destination/bootstrap/stage1",
	"stage2": "gs://wolfi-production-registry-destination/bootstrap/stage2",
	"stage3": "gs://wolfi-production-registry-destination/bootstrap/stage3",
}

func GenerateIndex() *cobra.Command {
	var arch, bucket, signingKey string
	var publish bool
	cmd := &cobra.Command{
		Use: "generate-index",
		Long: `This command generates an APKINDEX from the contents of a remote bucket.

Specify the bucket with --bucket. The default is "wolfi", the main prod Wolfi bucket.
Other acceptable values include "stage1", "stage2" and "stage3" for the bootstrap buckets.
Otherwise, specify any GCS bucket location with the gs:// prefix.

If --signing-key is passed, the APKINDEX will be signed with that key.

If --publish is passed, the APKINDEX will be published back to the bucket.
Otherwise it's written to APKINDEX.tar.gz.
`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			// Map a friendly string like "wolfi" to its bucket.
			if got, found := buckets[bucket]; found {
				bucket = got
			}
			if !strings.HasPrefix(bucket, "gs://") {
				return errors.New("--bucket must have gs:// prefix")
			}

			if signingKey != "" {
				k, err := os.Open(signingKey)
				if err != nil {
					return err
				}
				defer k.Close()
			}

			if publish && signingKey == "" {
				return errors.New("cowardly refusing to publish APKINDEX without signing; if --publish is true, then --signing-key must be passed")
			}

			idx := &repository.ApkIndex{}

			bkt, prefix, _ := strings.Cut(strings.TrimPrefix(bucket, "gs://"), "/")
			client, err := storage.NewClient(ctx)
			if err != nil {
				return err
			}
			b := client.Bucket(bkt)
			it := b.Objects(ctx, &storage.Query{
				Prefix: path.Join(prefix, arch),
			})
			errg, wctx := errgroup.WithContext(ctx)
			errg.SetLimit(runtime.NumCPU())
			var mu sync.Mutex
			for {
				attrs, err := it.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					return err
				}
				if !strings.HasSuffix(attrs.Name, ".apk") {
					continue
				}

				log.Println("-", attrs.Name)

				errg.Go(func() error {
					r, err := b.Object(attrs.Name).NewReader(wctx)
					if err != nil {
						return err
					}
					apk, err := repository.ParsePackage(r)
					if err != nil {
						return err
					}
					apk.Size = uint64(attrs.Size)
					mu.Lock()
					defer mu.Unlock()
					idx.Packages = append(idx.Packages, apk)
					return nil
				})
			}

			if err := errg.Wait(); err != nil {
				return err
			}
			sort.Slice(idx.Packages, func(i, j int) bool {
				if idx.Packages[i].Name == idx.Packages[j].Name {
					return idx.Packages[i].Version < idx.Packages[j].Version
				}
				return idx.Packages[i].Name < idx.Packages[j].Name
			})

			r, err := repository.ArchiveFromIndex(idx)
			if err != nil {
				return err
			}

			var tmp string
			{
				// Write index to tempfile.
				f, err := os.CreateTemp("", "")
				if err != nil {
					return err
				}
				defer f.Close()
				if _, err := io.Copy(f, r); err != nil {
					return err
				}
				tmp = f.Name()
			}

			f, err := os.Open(tmp)
			if err != nil {
				return err
			}
			defer f.Close()

			if signingKey != "" {
				log.Printf("signing index with %s", signingKey)
				if err := melange.SignIndexCmd(ctx, signingKey, f.Name()); err != nil {
					return fmt.Errorf("error signing index: %w", err)
				}
			} else {
				log.Println("no --signing-key provided, not signing index")
			}

			if publish {
				log.Println("publishing APKINDEX to repo")
				w := client.Bucket(bkt).Object(path.Join(prefix, arch, "APKINDEX.tar.gz")).NewWriter(ctx)
				w.CacheControl = "no-cache"
				defer func() {
					// Closing the GCS object also flushes remaining data, and so it can fail.
					if err := w.Close(); err != nil {
						log.Fatalf("error closing object: %v", err)
					}
				}()
				if _, err := io.Copy(w, f); err != nil {
					return err
				}
			} else {
				log.Println("writing APKINDEX.tar.gz")
				i, err := os.Create("APKINDEX.tar.gz")
				if err != nil {
					return err
				}
				defer i.Close()
				if _, err := io.Copy(i, f); err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&arch, "arch", "x86_64", "arch of package to get")
	cmd.Flags().StringVar(&bucket, "bucket", "wolfi", "bucket to get packages from")
	cmd.Flags().BoolVar(&publish, "publish", false, "if true, publish APKINDEX.tar.gz back to the repo (must be signed)")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "if set, key to use to sign the index")
	return cmd
}
