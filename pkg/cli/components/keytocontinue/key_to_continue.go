package keytocontinue

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/breather"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/ctrlcwrapper"
)

var _ tea.Model = (*Model)(nil)

type Model struct {
	// key is the key that the user must press to continue. It must be a valid
	// tea.KeyMsg string.
	key string

	// purpose is a string that describes the purpose of the key press. It should
	// typically start with "to" and end with "...", e.g. "to continue...".
	purpose string

	programAboutToEnd bool
	breather          breather.Model
}

func New(key, purpose string) Model {
	return Model{
		key:      key,
		purpose:  purpose,
		breather: breather.New(">"),
	}
}

func (m Model) Init() tea.Cmd {
	return m.breather.Init()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == m.key {
			m.programAboutToEnd = true
			return m, tea.Quit
		}

	case ctrlcwrapper.AboutToExitMsg:
		m.programAboutToEnd = true
		return m, ctrlcwrapper.InnerIsReady

	case breather.TickMsg:
		var cmd tea.Cmd
		m.breather, cmd = m.breather.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) View() string {
	if m.programAboutToEnd {
		return ""
	}

	return fmt.Sprintf(
		"%s Press %s %s\n",
		m.breather.View(),
		keyStyle.Render(m.key),
		m.purpose,
	)
}

var keyStyle = lipgloss.NewStyle().Bold(true)
