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
	items               []T
	itemRendererFunc    func(T) string
	customActions       []CustomAction[T]
	selected            int
	picked              bool
	aboutToExit         bool
	breather            breather.Model
	messageForZeroItems string

	// Error is the error that occurred during the picker's lifecycle, if any.
	Error error
}

type Options[T any] struct {
	// Items is the list of items to display, from which the user can pick.
	Items []T

	// MessageForZeroItems is the message to display when there are no items to
	// list.
	MessageForZeroItems string

	// ItemRenderFunc is the function to use to render each item in the list. If
	// nil, the item will be rendered via fmt.Sprintf("%v", item).
	ItemRenderFunc func(T) string

	// CustomActions is a list of custom actions that the user can take.
	CustomActions []CustomAction[T]
}

// New returns a new picker model. The render function is used to render each
// item in the list.
func New[T any](opts Options[T]) Model[T] {
	return Model[T]{
		items:               opts.Items,
		itemRendererFunc:    opts.ItemRenderFunc,
		customActions:       opts.CustomActions,
		messageForZeroItems: opts.MessageForZeroItems,
		breather:            breather.New(">"),
	}
}

type CustomAction[T any] struct {
	// Key is the key that the user should press to select this action.
	Key string

	// Description is a short description of what this action does, used in help
	// text.
	//
	// For example, in the help text "o to open.", "to open" is the description.
	Description string

	// Do is the function to call when the user presses the key for this action.
	Do func(selected T) tea.Cmd
}

// ErrCmd returns a command that will cause the picker to display an error
// message and exit.
func ErrCmd(err error) tea.Cmd {
	return func() tea.Msg {
		return ErrMsg(err)
	}
}

// ErrMsg is a bubbletea message that indicates an error occurred during the
// picker's lifecycle.
type ErrMsg error

func (m Model[T]) Init() tea.Cmd {
	return m.breather.Init()
}

func (m Model[T]) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case ctrlcwrapper.AboutToExitMsg:
		m.aboutToExit = true
		return m, ctrlcwrapper.InnerIsReady

	case ErrMsg:
		m.Error = msg
		return m, tea.Quit

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
			m.picked = true
			m.aboutToExit = true
			return m, tea.Quit
		}

		for _, action := range m.customActions {
			if msg.String() == action.Key {
				if action.Do == nil {
					continue
				}

				var selected T
				if len(m.items) > 0 {
					selected = m.items[m.selected]
				}
				return m, action.Do(selected)
			}
		}

	case breather.TickMsg:
		var cmd tea.Cmd
		m.breather, cmd = m.breather.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model[T]) View() string {
	sb := new(strings.Builder)

	if len(m.items) == 0 {
		sb.WriteString(m.messageForZeroItems + "\n")
	}

	var breatherView string
	if m.aboutToExit {
		// Don't animate, picking and/or exiting has happened.
		breatherView = m.breather.ViewStatic()
	} else {
		breatherView = m.breather.View()
	}

	for i, item := range m.items {
		if i == m.selected {
			sb.WriteString(fmt.Sprintf("%s %s\n", breatherView, m.itemRendererFunc(item)))
			continue
		}

		if !m.aboutToExit {
			sb.WriteString(fmt.Sprintf("  %s\n", m.itemRendererFunc(item)))
		}
	}

	sb.WriteString("\n")

	if !m.aboutToExit {
		if count := len(m.items); count > 0 {
			if count > 1 {
				sb.WriteString(helpChangeSelection + " ")
			}

			sb.WriteString(helpConfirm + "\n")
		}

		for _, action := range m.customActions {
			sb.WriteString(fmt.Sprintf(
				"%s %s\n",
				styleHelpKey.Render(action.Key),
				styleHelpExplanation.Render(action.Description+"."),
			))
		}
	}

	return sb.String()
}

// Picked returns the item that was picked by the user, if any. If no item has
// been picked, this returns nil.
func (m Model[T]) Picked() *T {
	if !m.picked {
		// The user hasn't picked anything yet.
		return nil
	}

	picked := m.items[m.selected]
	return &picked
}

var (
	helpChangeSelection = fmt.Sprintf(
		"%s %s",
		styleHelpKey.Render("↑/↓"),
		styleHelpExplanation.Render("to change selection."),
	)

	helpConfirm = fmt.Sprintf(
		"%s %s",
		styleHelpKey.Render("enter"),
		styleHelpExplanation.Render("to confirm."),
	)
)

var (
	styleHelpKey         = styles.FaintAccent().Copy().Bold(true)
	styleHelpExplanation = styles.Faint().Copy()
)
