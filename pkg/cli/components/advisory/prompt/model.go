package prompt

import (
	"errors"
	"regexp"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/advisory/field"
)

type Model struct {
	// internal data
	focusIndex                 int
	fields                     []field.Field
	allowedPackagesFunc        func() []string
	allowedVulnerabilitiesFunc func(packageName string) []string
	allowedFixedVersionsFunc   func(packageName string) []string

	// input/output data
	Request advisory.Request

	// output data

	// EarlyExit is set to true if the user asks to exit the prompt early.
	EarlyExit bool
}

func (m Model) newPackageFieldConfig() field.TextFieldConfiguration {
	allowedValues := m.allowedPackagesFunc()

	return field.TextFieldConfiguration{
		Prompt: "Package: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.Package = value
			return req
		},
		AllowedValues:     allowedValues,
		EmptyValueHelpMsg: "Type to find a package.",
		NoMatchHelpMsg:    "No matching package found.",
		ValidationRules: []field.TextValidationRule{
			field.NotEmpty,
		},
	}
}

var cveIDRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

var ValidCVEID = field.TextValidationRule(func(value string) error {
	if !cveIDRegex.MatchString(value) {
		return errors.New("must be a CVE ID")
	}

	return nil
})

func (m Model) newVulnerabilityFieldConfig() field.TextFieldConfiguration {
	allowedValues := m.allowedVulnerabilitiesFunc(m.Request.Package)

	return field.TextFieldConfiguration{
		Prompt: "Vulnerability: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.Vulnerability = value
			return req
		},
		EmptyValueHelpMsg: "Provide a valid vulnerability ID.",
		ValidationRules: []field.TextValidationRule{
			field.NotEmpty,
			ValidCVEID,
		},
		AllowedValues: allowedValues,
	}
}

func (m Model) newStatusFieldConfig() field.ListFieldConfiguration {
	return field.ListFieldConfiguration{
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
}

func (m Model) newActionFieldConfig() field.TextFieldConfiguration {
	return field.TextFieldConfiguration{
		Prompt: "Action: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.Action = value
			return req
		},
	}
}

func (m Model) newImpactFieldConfig() field.TextFieldConfiguration {
	return field.TextFieldConfiguration{
		Prompt: "Impact: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.Impact = value
			return req
		},
		ValidationRules: []field.TextValidationRule{
			func(_ string) error {
				return nil
			},
		},
	}
}

func (m Model) newJustificationFieldConfig() field.ListFieldConfiguration {
	return field.ListFieldConfiguration{
		Prompt:  "Justification: ",
		Options: vex.Justifications(),
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.Justification = vex.Justification(value)
			return req
		},
	}
}

func (m Model) newFixedVersionFieldConfig(packageName string) field.TextFieldConfiguration {
	allowedVersions := m.allowedFixedVersionsFunc(packageName)

	cfg := field.TextFieldConfiguration{
		Prompt: "Fixed Version: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.FixedVersion = value
			return req
		},
		AllowedValues:  allowedVersions,
		NoMatchHelpMsg: "No matching version found.",
	}

	if len(allowedVersions) >= 1 {
		cfg.DefaultSuggestion = allowedVersions[0]
	}

	return cfg
}

type Configuration struct {
	Request                    advisory.Request
	AllowedPackagesFunc        func() []string
	AllowedVulnerabilitiesFunc func(packageName string) []string
	AllowedFixedVersionsFunc   func(packageName string) []string
}

func New(config Configuration) Model {
	m := Model{
		Request: config.Request,

		allowedPackagesFunc:        config.AllowedPackagesFunc,
		allowedVulnerabilitiesFunc: config.AllowedVulnerabilitiesFunc,
		allowedFixedVersionsFunc:   config.AllowedFixedVersionsFunc,
	}

	m, _ = m.addMissingFields()

	m.fields[0], _ = m.fields[0].SetFocus()

	return m
}

// addMissingFields returns an updated model, and a bool indicating whether any
// fields needed to be added.
func (m Model) addMissingFields() (Model, bool) {
	if m.Request.Package == "" {
		f := field.NewTextField(m.newPackageFieldConfig())
		m.fields = append(m.fields, f)
		return m, true
	}

	if m.Request.Vulnerability == "" {
		f := field.NewTextField(m.newVulnerabilityFieldConfig())
		m.fields = append(m.fields, f)
		return m, true
	}

	if m.Request.Status == "" {
		f := field.NewListField(m.newStatusFieldConfig())
		m.fields = append(m.fields, f)
		return m, true
	}

	switch m.Request.Status {
	case vex.StatusFixed:
		if m.Request.FixedVersion == "" {
			f := field.NewTextField(m.newFixedVersionFieldConfig(m.Request.Package))
			m.fields = append(m.fields, f)
			return m, true
		}

	case vex.StatusAffected:
		if m.Request.Action == "" {
			f := field.NewTextField(m.newActionFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}

	case vex.StatusNotAffected:
		if m.Request.Justification == "" {
			f := field.NewListField(m.newJustificationFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}

		if m.Request.Impact == "" {
			f := field.NewTextField(m.newImpactFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}
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

			sel, err := sel.SubmitValue()
			if err != nil {
				var inner field.ErrValueNotAccepted
				if errors.As(err, &inner) {
					// Value isn't ready to be submitted; do nothing.
					return m, nil
				}

				// TODO: Handle other errors
			}

			m.Request = sel.UpdateRequest(m.Request)
			m.fields[m.focusIndex] = sel

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
