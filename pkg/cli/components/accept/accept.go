package accept

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
)

type Model struct {
	// Accepted is true if the message was accepted by the user.
	Accepted bool
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if ok && keyMsg.String() == "enter" {
		m.Accepted = true
	}

	return m, nil
}

func (m Model) View() string {
	if m.Accepted {
		return ""
	}

	return fmt.Sprintf("%s\n", helpAccept)
}

var (
	helpAccept = fmt.Sprintf(
		"%s %s",
		styleHelpKey.Render("enter"),
		styleHelpExplanation.Render("to move on."),
	)
)

var (
	styleHelpKey         = styles.FaintAccent().Bold(true)
	styleHelpExplanation = styles.Faint()
)
