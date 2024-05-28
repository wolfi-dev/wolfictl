package prompt

import (
	"errors"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/advisory/field"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
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

const (
	fieldIDPackage                = "package"
	fieldIDVulnerability          = "vulnerability"
	fieldIDEventType              = "event-type"
	fieldIDFixedVersion           = "fixed-version"
	fieldIDTruePositiveNote       = "true-positive-note"
	fieldIDFalsePositiveType      = "false-positive-type"
	fieldIDFalsePositiveNote      = "false-positive-note"
	fieldIDFixNotPlannedNote      = "fix-not-planned-note"
	fieldIDAnalysisNotPlannedNote = "analysis-not-planned-note"
	fieldIDPendingUpstreamFixNote = "pending-upstream-fix-note"
)

func (m Model) newPackageFieldConfig() field.TextFieldConfiguration {
	allowedValues := m.allowedPackagesFunc()

	return field.TextFieldConfiguration{
		ID:     fieldIDPackage,
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

var validCVEID = field.TextValidationRule(vuln.ValidateID)

func (m Model) newVulnerabilityFieldConfig() field.TextFieldConfiguration {
	allowedValues := m.allowedVulnerabilitiesFunc(m.Request.Package)

	return field.TextFieldConfiguration{
		ID:     fieldIDVulnerability,
		Prompt: "Vulnerability: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.Aliases = append(req.Aliases, value)
			return req
		},
		EmptyValueHelpMsg: "Provide a valid vulnerability ID.",
		ValidationRules: []field.TextValidationRule{
			field.NotEmpty,
			validCVEID,
		},
		AllowedValues: allowedValues,
	}
}

func (m Model) newTypeFieldConfig() field.ListFieldConfiguration {
	return field.ListFieldConfiguration{
		ID:      fieldIDEventType,
		Prompt:  "Type: ",
		Options: v2.EventTypes,
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			req.Event.Type = value
			return req
		},
	}
}

func (m Model) newTruePositiveNoteFieldConfig() field.TextFieldConfiguration {
	return field.TextFieldConfiguration{
		ID:     fieldIDTruePositiveNote,
		Prompt: "Note: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			if value == "" {
				req.Event.Data = nil
				return req
			}

			if req.Event.Data == nil {
				req.Event.Data = v2.TruePositiveDetermination{
					Note: value,
				}
			}

			return req
		},
	}
}

func (m Model) newFixNotPlannedNoteFieldConfig() field.TextFieldConfiguration {
	return field.TextFieldConfiguration{
		ID:     fieldIDFixNotPlannedNote,
		Prompt: "Note: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			if req.Event.Data == nil {
				req.Event.Data = v2.FixNotPlanned{
					Note: value,
				}
			} else if data, ok := req.Event.Data.(v2.FixNotPlanned); ok {
				data.Note = value
				req.Event.Data = data
			}
			return req
		},
		ValidationRules: []field.TextValidationRule{
			field.NotEmpty,
		},
	}
}

func (m Model) newAnalysisNotPlannedNoteFieldConfig() field.TextFieldConfiguration {
	return field.TextFieldConfiguration{
		ID:     fieldIDAnalysisNotPlannedNote,
		Prompt: "Note: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			if req.Event.Data == nil {
				req.Event.Data = v2.AnalysisNotPlanned{
					Note: value,
				}
			} else if data, ok := req.Event.Data.(v2.AnalysisNotPlanned); ok {
				data.Note = value
				req.Event.Data = data
			}
			return req
		},
		ValidationRules: []field.TextValidationRule{
			field.NotEmpty,
		},
	}
}

func (m Model) newPendingUpstreamReleaseNoteFieldConfig() field.TextFieldConfiguration {
	return field.TextFieldConfiguration{
		ID:     fieldIDPendingUpstreamFixNote,
		Prompt: "Note: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			if req.Event.Data == nil {
				req.Event.Data = v2.PendingUpstreamFix{
					Note: value,
				}
			} else if data, ok := req.Event.Data.(v2.PendingUpstreamFix); ok {
				data.Note = value
				req.Event.Data = data
			}
			return req
		},
		ValidationRules: []field.TextValidationRule{
			field.NotEmpty,
		},
	}
}

func (m Model) newFalsePositiveNoteFieldConfig() field.TextFieldConfiguration {
	return field.TextFieldConfiguration{
		ID:     fieldIDFalsePositiveNote,
		Prompt: "Note: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			if req.Event.Data == nil {
				req.Event.Data = v2.FalsePositiveDetermination{
					Note: value,
				}
			} else if data, ok := req.Event.Data.(v2.FalsePositiveDetermination); ok {
				data.Note = value
				req.Event.Data = data
			}
			return req
		},
		ValidationRules: []field.TextValidationRule{
			field.NotEmpty,
		},
	}
}

func (m Model) newFalsePositiveTypeFieldConfig() field.ListFieldConfiguration {
	return field.ListFieldConfiguration{
		ID:      fieldIDFalsePositiveType,
		Prompt:  "False Positive Type: ",
		Options: v2.FPTypes,
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			if req.Event.Data == nil {
				req.Event.Data = v2.FalsePositiveDetermination{
					Type: value,
				}
			} else if data, ok := req.Event.Data.(v2.FalsePositiveDetermination); ok {
				data.Type = value
				req.Event.Data = data
			}
			return req
		},
	}
}

func (m Model) newFixedVersionFieldConfig(packageName string) field.TextFieldConfiguration {
	allowedVersions := m.allowedFixedVersionsFunc(packageName)

	cfg := field.TextFieldConfiguration{
		ID:     fieldIDFixedVersion,
		Prompt: "Fixed Version: ",
		RequestUpdater: func(value string, req advisory.Request) advisory.Request {
			if req.Event.Data == nil {
				req.Event.Data = v2.Fixed{
					FixedVersion: value,
				}
			}
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

func (m Model) hasFieldWithID(id string) bool {
	for _, f := range m.fields {
		if f.ID() == id {
			return true
		}
	}

	return false
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

	if len(m.Request.Aliases) == 0 {
		f := field.NewTextField(m.newVulnerabilityFieldConfig())
		m.fields = append(m.fields, f)
		return m, true
	}

	if m.Request.Event.Type == "" {
		f := field.NewListField(m.newTypeFieldConfig())
		m.fields = append(m.fields, f)
		return m, true
	}

	switch e := m.Request.Event; e.Type {
	case v2.EventTypeFixed:
		if data, ok := e.Data.(v2.Fixed); !ok || data.FixedVersion == "" {
			f := field.NewTextField(m.newFixedVersionFieldConfig(m.Request.Package))
			m.fields = append(m.fields, f)
			return m, true
		}

	case v2.EventTypeTruePositiveDetermination:
		// This field is optional. If we've already asked for it, don't ask again.
		if m.hasFieldWithID(fieldIDTruePositiveNote) {
			return m, false
		}

		if _, ok := e.Data.(v2.TruePositiveDetermination); !ok {
			f := field.NewTextField(m.newTruePositiveNoteFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}

	case v2.EventTypeFalsePositiveDetermination:
		if data, ok := e.Data.(v2.FalsePositiveDetermination); !ok || data.Type == "" {
			f := field.NewListField(m.newFalsePositiveTypeFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}

		if data, ok := e.Data.(v2.FalsePositiveDetermination); !ok || data.Note == "" {
			f := field.NewTextField(m.newFalsePositiveNoteFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}

	case v2.EventTypeFixNotPlanned:
		if data, ok := e.Data.(v2.FixNotPlanned); !ok || data.Note == "" {
			f := field.NewTextField(m.newFixNotPlannedNoteFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}

	case v2.EventTypeAnalysisNotPlanned:
		if data, ok := e.Data.(v2.AnalysisNotPlanned); !ok || data.Note == "" {
			f := field.NewTextField(m.newAnalysisNotPlannedNoteFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}

	case v2.EventTypePendingUpstreamFix:
		if data, ok := e.Data.(v2.PendingUpstreamFix); !ok || data.Note == "" {
			f := field.NewTextField(m.newPendingUpstreamReleaseNoteFieldConfig())
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

			// We should move this business logic snippet somewhere else eventually.
			if m.Request.Event.Type == v2.EventTypeDetection {
				m.Request.Event.Data = v2.Detection{Type: v2.DetectionTypeManual}
			}

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
