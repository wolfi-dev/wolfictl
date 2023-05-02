package field

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
)

type TextField struct {
	input          textinput.Model
	done           bool
	requestUpdater func(value string, req advisory.Request) advisory.Request
}

type TextFieldConfiguration struct {
	Prompt         string
	RequestUpdater func(value string, req advisory.Request) advisory.Request
}

func NewTextField(cfg TextFieldConfiguration) TextField {
	t := textinput.New()
	t.CursorStyle = cursorStyle
	t.CharLimit = 32

	t.Prompt = cfg.Prompt

	return TextField{
		input:          t,
		requestUpdater: cfg.RequestUpdater,
	}
}

func (f TextField) UpdateRequest(value string, req advisory.Request) advisory.Request {
	return f.requestUpdater(value, req)
}

func (f TextField) Update(msg tea.Msg) (Field, tea.Cmd) {
	m, cmd := f.input.Update(msg)
	f.input = m
	return f, cmd
}

func (f TextField) SetDone() Field {
	f.done = true
	return f
}

func (f TextField) SetBlur() Field {
	f.input.Blur()

	f.input.PromptStyle = noStyle
	f.input.TextStyle = noStyle

	return f
}

func (f TextField) SetFocus() (Field, tea.Cmd) {
	cmd := f.input.Focus()

	f.input.PromptStyle = focusedStyle
	f.input.TextStyle = focusedStyle

	return f, cmd
}

func (f TextField) IsDone() bool {
	return f.done
}

func (f TextField) Value() string {
	return f.input.Value()
}

func (f TextField) View() string {
	var lines []string

	lines = append(lines, f.input.View())

	if !f.done {
		helpText := fmt.Sprintf(
			"%s %s %s %s",
			cursorModeHelpStyle.Render("Enter"),
			helpStyle.Render("to confirm value."),
			cursorModeHelpStyle.Render("Ctrl+C"),
			helpStyle.Render("to quit."),
		)

		lines = append(lines, helpText)
	}

	return strings.Join(lines, "\n")
}
