package picker

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/breather"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/ctrlcwrapper"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
)

type Model[T any] struct {
	// Picked is the item that was picked by the user.
	Picked T

	items            []T
	itemRendererFunc func(T) string
	selected         int
	aboutToExit      bool
	breather         breather.Model
}

// New returns a new picker model. The render function is used to render each
// item in the list.
func New[T any](items []T, render func(T) string) Model[T] {
	return Model[T]{
		items:            items,
		itemRendererFunc: render,
		breather:         breather.New(">"),
	}
}

func (m Model[T]) Init() tea.Cmd {
	return m.breather.Init()
}

func (m Model[T]) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case ctrlcwrapper.AboutToExitMsg:
		m.aboutToExit = true
		return m, ctrlcwrapper.InnerIsReady

	case tea.KeyMsg:
		switch msg.String() {
		case "up":
			if m.selected > 0 {
				m.selected--
			}

		case "down":
			if m.selected < len(m.items)-1 {
				m.selected++
			}

		case "enter":
			m.Picked = m.items[m.selected]
			m.aboutToExit = true
			return m, tea.Quit
		}

	case breather.TickMsg:
		var cmd tea.Cmd
		m.breather, cmd = m.breather.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model[T]) View() string {
	if len(m.items) == 0 {
		// TODO: handle this better!
		return "(No items to display)"
	}

	sb := new(strings.Builder)
	for i, item := range m.items {
		if i == m.selected {
			sb.WriteString(fmt.Sprintf("%s %s\n", m.breather.View(), m.itemRendererFunc(item)))
			continue
		}

		sb.WriteString(fmt.Sprintf("  %s\n", m.itemRendererFunc(item)))
	}

	sb.WriteString("\n")

	if !m.aboutToExit {
		sb.WriteString(help)
	}

	return sb.String()
}

var help = fmt.Sprintf(
	"%s %s %s %s\n",
	styleHelpKey.Render("↑/↓"),
	styleHelpExplanation.Render("to change selection."),
	styleHelpKey.Render("enter"),
	styleHelpExplanation.Render("to confirm your choice."),
)

var (
	styleHelpKey         = styles.FaintAccent().Copy().Bold(true)
	styleHelpExplanation = styles.Faint().Copy()
)
