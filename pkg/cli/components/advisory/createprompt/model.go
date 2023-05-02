package createprompt

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/advisory/field"
)

type Model struct {
	// internal data
	focusIndex int
	fields     []field.Field

	// input/output data
	Request advisory.Request

	// output data
	EarlyExit bool
}

var (
	packageFieldConfig = field.TextFieldConfiguration{
		Prompt: "Package: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.Package = value
			return req
		},
	}

	vulnerabilityFieldConfig = field.TextFieldConfiguration{
		Prompt: "Vulnerability: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.Vulnerability = value
			return req
		},
	}

	statusFieldConfig = field.ListFieldConfiguration{
		Prompt: "Status: ",
		Options: []string{
			string(vex.StatusFixed),
			string(vex.StatusNotAffected),
			string(vex.StatusAffected),
			string(vex.StatusUnderInvestigation),
		},
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.Status = vex.Status(value)
			return req
		},
	}

	actionFieldConfig = field.TextFieldConfiguration{
		Prompt: "Action: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.Action = value
			return req
		},
	}

	justificationFieldConfig = field.ListFieldConfiguration{
		Prompt:  "Justification: ",
		Options: vex.Justifications(),
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.Justification = vex.Justification(value)
			return req
		},
	}

	// TODO: default to latest
	fixedVersionFieldConfig = field.TextFieldConfiguration{
		Prompt: "Fixed Version: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.FixedVersion = value
			return req
		},
	}
)

func New(cr advisory.Request) Model {
	m := Model{
		Request:    cr,
		focusIndex: 0,
	}

	m, _ = m.addMissingFields()

	m.fields[0], _ = m.fields[0].SetFocus()

	return m
}

// addMissingFields returns an updated model, and a bool indicating whether any
// fields needed to be added.
func (m Model) addMissingFields() (Model, bool) {
	if m.Request.Package == "" {
		f := field.NewTextField(packageFieldConfig)
		m.fields = append(m.fields, f)
		return m, true
	}

	if m.Request.Vulnerability == "" {
		f := field.NewTextField(vulnerabilityFieldConfig)
		m.fields = append(m.fields, f)
		return m, true
	}

	if m.Request.Status == "" {
		f := field.NewListField(statusFieldConfig)
		m.fields = append(m.fields, f)
		return m, true
	}

	switch m.Request.Status {
	case vex.StatusFixed:
		if m.Request.FixedVersion == "" {
			f := field.NewTextField(fixedVersionFieldConfig)
			m.fields = append(m.fields, f)
			return m, true
		}

	case vex.StatusAffected:
		if m.Request.Action == "" {
			f := field.NewTextField(actionFieldConfig)
			m.fields = append(m.fields, f)
			return m, true
		}

	case vex.StatusNotAffected:
		if m.Request.Justification == "" {
			f := field.NewListField(justificationFieldConfig)
			m.fields = append(m.fields, f)
			return m, true
		}

		// TODO: Prompt for Impact if folks want to enter it. (There's a gotcha if adding it if left blank.)
	}

	return m, false
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.String() {
		case "ctrl+c":
			m.EarlyExit = true
			return m, tea.Quit

		case "enter":
			// Handle field entry completion

			sel := m.fields[m.focusIndex]

			if f, ok := sel.(field.TextField); ok {
				// for now, text fields can't be left empty; so 'enter' should do nothing.
				if strings.TrimSpace(f.Value()) == "" {
					// do nothing
					return m, nil
				}
			}

			m.Request = sel.UpdateRequest(sel.Value(), m.Request)
			m.fields[m.focusIndex] = sel.SetDone()

			// Move on to the next field

			m.focusIndex++

			var moreFieldsAdded bool
			m, moreFieldsAdded = m.addMissingFields()

			if !moreFieldsAdded {
				if m.focusIndex == len(m.fields) {
					return m, tea.Quit
				}
			}

			cmds := make([]tea.Cmd, len(m.fields))
			for i := 0; i <= len(m.fields)-1; i++ {
				if i == m.focusIndex {
					m.fields[i], cmds[i] = m.fields[i].SetFocus()
					continue
				}

				m.fields[i] = m.fields[i].SetBlur()
			}

			return m, tea.Batch(cmds...)
		}
	}

	// Handle character input and blinking
	m, cmd := m.updateFields(msg)

	return m, cmd
}

func (m Model) View() string {
	view := ""

	for _, f := range m.fields {
		view += f.View() + "\n"

		if !f.IsDone() {
			// Don't show more than one "not done" field at a time
			break
		}
	}

	return view
}

func (m Model) updateFields(msg tea.Msg) (Model, tea.Cmd) {
	cmds := make([]tea.Cmd, len(m.fields))

	// Only text inputs with Focus() set will respond, so it's safe to simply
	// update all of them here without any further logic.
	for i := range m.fields {
		m.fields[i], cmds[i] = m.fields[i].Update(msg)
	}

	return m, tea.Batch(cmds...)
}
