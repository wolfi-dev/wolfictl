package field

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/list"
)

type ListField struct {
	prompt         string
	input          list.Model
	done           bool
	requestUpdater func(value string, req advisory.Request) advisory.Request
}

type ListFieldConfiguration struct {
	Prompt         string
	Options        []string
	RequestUpdater func(value string, req advisory.Request) advisory.Request
}

func NewListField(cfg ListFieldConfiguration) ListField {
	l := list.New(cfg.Prompt, cfg.Options)
	l.SelectedStyle = focusedStyle
	l.UnselectedStyle = blurredStyle

	return ListField{
		prompt:         cfg.Prompt,
		input:          l,
		requestUpdater: cfg.RequestUpdater,
	}
}

func (f ListField) UpdateRequest(value string, req advisory.Request) advisory.Request {
	return f.requestUpdater(value, req)
}

func (f ListField) Update(msg tea.Msg) (Field, tea.Cmd) {
	var cmd tea.Cmd

	if f.input.Focused() {
		f.input, cmd = f.input.Update(msg)
	}

	return f, cmd
}

func (f ListField) SetDone() Field {
	f.done = true
	return f
}

func (f ListField) SetBlur() Field {
	f.input = f.input.Blur()
	return f
}

func (f ListField) SetFocus() (Field, tea.Cmd) {
	f.input = f.input.Focus()
	return f, nil
}

func (f ListField) IsDone() bool {
	return f.done
}

func (f ListField) Value() string {
	return f.input.SelectedItem()
}

func (f ListField) View() string {
	var lines []string

	if !f.done {
		lines = append(lines, f.input.View())
		helpText := fmt.Sprintf(
			"%s %s %s %s",
			cursorModeHelpStyle.Render("Enter"),
			helpStyle.Render("to confirm value."),
			cursorModeHelpStyle.Render("Ctrl+C"),
			helpStyle.Render("to quit."),
		)

		lines = append(lines, helpText)
	} else {
		lines = append(lines, f.prompt+"\n  "+f.input.SelectedItem())
	}

	return strings.Join(lines, "\n")
}
