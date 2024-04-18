package textinput

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// Model wraps Charm's textinput.Model to make it an actual tea.Model.
//
// I'm not 100% sure why this is necessary, so I've asked on an issue:
// https://github.com/charmbracelet/bubbles/issues/371#issuecomment-2062787557.
type Model struct {
	Inner textinput.Model
}

// New returns a new text input model.
func New() Model {
	ti := textinput.New()
	ti.Focus()

	return Model{
		Inner: ti,
	}
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.Inner, cmd = m.Inner.Update(msg)
	return m, cmd
}

func (m Model) View() string {
	return m.Inner.View()
}
