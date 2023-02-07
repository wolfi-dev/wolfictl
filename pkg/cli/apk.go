package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"gitlab.alpinelinux.org/alpine/go/repository"
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
				idx, err := index(arch, repo)
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

			idx, err := index(arch, repo)
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

func index(arch, repo string) (*repository.ApkIndex, error) {
	url := fmt.Sprintf("%s/%s/APKINDEX.tar.gz", repo, arch)
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("GET %s (%d): %s", url, resp.StatusCode, b)
	}

	return repository.IndexFromArchive(resp.Body)
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
		if msg.String() == "ctrl+c" {
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
