package field

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/list"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
)

type ListField struct {
	id                   string
	prompt               string
	input                list.Model
	done                 bool
	requestParamsUpdater func(value string, p advisory.RequestParams) advisory.RequestParams
}

type ListFieldConfiguration struct {
	// ID is a unique identifier for the field.
	ID string

	Prompt               string
	Options              []string
	RequestParamsUpdater func(value string, p advisory.RequestParams) advisory.RequestParams
}

func NewListField(cfg ListFieldConfiguration) ListField {
	l := list.New(cfg.Prompt, cfg.Options)
	l.SelectedStyle = styles.Accented()
	l.UnselectedStyle = styles.Secondary()

	return ListField{
		id:                   cfg.ID,
		prompt:               cfg.Prompt,
		input:                l,
		requestParamsUpdater: cfg.RequestParamsUpdater,
	}
}

func (f ListField) ID() string {
	return f.id
}

func (f ListField) UpdateRequestParams(p advisory.RequestParams) advisory.RequestParams {
	value := f.Value()
	return f.requestParamsUpdater(value, p)
}

func (f ListField) SubmitValue() (Field, error) {
	return f.setDone(), nil
}

func (f ListField) Update(msg tea.Msg) (Field, tea.Cmd) {
	if f.done {
		return f, nil
	}

	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)

	return f, cmd
}

func (f ListField) setDone() ListField {
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
			helpKeyStyle.Render("Enter"),
			helpExplanationStyle.Render("to confirm."),
			helpKeyStyle.Render("Ctrl+C"),
			helpExplanationStyle.Render("to quit."),
		)

		lines = append(lines, helpText)
	} else {
		lines = append(lines, f.prompt+"\n  "+f.input.SelectedItem())
	}

	return strings.Join(lines, "\n")
}
