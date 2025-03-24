package prompt

import (
	"errors"
	"fmt"
	"strings"

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
	allowedPackagesFunc        func() ([]string, error)
	allowedVulnerabilitiesFunc func(packageName string) ([]string, error)
	allowedFixedVersionsFunc   func(packageName string) ([]string, error)

	// input/output data
	RequestParams advisory.RequestParams

	// output data

	// EarlyExit is set to true if the user asks to exit the prompt early.
	EarlyExit bool

	// Err is set if an error occurs during the prompt.
	Err error
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

func (m Model) newPackageFieldConfig() (field.TextFieldConfiguration, error) {
	allowedValues, err := m.allowedPackagesFunc()
	if err != nil {
		return field.TextFieldConfiguration{}, fmt.Errorf("getting list of allowed packages: %w", err)
	}

	return field.TextFieldConfiguration{
		ID:     fieldIDPackage,
		Prompt: "Package: ",
		RequestParamsUpdater: func(value string, p advisory.RequestParams) advisory.RequestParams {
			names := strings.Split(value, ",")
			for _, name := range names {
				p.PackageNames = append(p.PackageNames, strings.TrimSpace(name))
			}
			return p
		},
		EmptyValueHelpMsg: "Type to find a package.",
		NoMatchHelpMsg:    "No matching package found.",
		ValidationRules: []field.TextValidationRule{
			field.NotEmpty,
		},
		AllowedValues: allowedValues,
	}, nil
}

func (m Model) newVulnerabilityFieldConfig() (field.TextFieldConfiguration, error) {
	var allowedValues []string

	// If there are multiple packages selected, disable the constraint on the
	// vulnerability field; otherwise, obtain the allowed values using the one
	// package name.
	if len(m.RequestParams.PackageNames) == 1 {
		allowed, err := m.allowedVulnerabilitiesFunc(m.RequestParams.PackageNames[0])
		if err != nil {
			return field.TextFieldConfiguration{}, fmt.Errorf("getting list of allowed vulnerabilities: %w", err)
		}
		allowedValues = allowed
	}

	return field.TextFieldConfiguration{
		ID:     fieldIDVulnerability,
		Prompt: "Vulnerability: ",
		RequestParamsUpdater: func(value string, p advisory.RequestParams) advisory.RequestParams {
			vulns := strings.Split(value, ",")
			for _, v := range vulns {
				p.Vulns = append(p.Vulns, strings.TrimSpace(v))
			}
			return p
		},
		EmptyValueHelpMsg: "Provide a valid vulnerability ID.",
		ValidationRules: []field.TextValidationRule{
			field.NotEmpty,
			vuln.ValidateID,
		},
		AllowedValues: allowedValues,
	}, nil
}

func (m Model) newTypeFieldConfig() field.ListFieldConfiguration {
	return field.ListFieldConfiguration{
		ID:     fieldIDEventType,
		Prompt: "Type: ",
		Options: []string{
			v2.EventTypeFixed,
			v2.EventTypeFalsePositiveDetermination,
			v2.EventTypeFixNotPlanned,
			v2.EventTypePendingUpstreamFix,
		},
		RequestParamsUpdater: func(value string, p advisory.RequestParams) advisory.RequestParams {
			p.EventType = value
			return p
		},
	}
}

func (m Model) newTruePositiveNoteFieldConfig() field.TextFieldConfiguration {
	return field.TextFieldConfiguration{
		ID:     fieldIDTruePositiveNote,
		Prompt: "Note: ",
		RequestParamsUpdater: func(value string, p advisory.RequestParams) advisory.RequestParams {
			p.TruePositiveNote = value
			return p
		},
	}
}

func (m Model) newFixNotPlannedNoteFieldConfig() field.TextFieldConfiguration {
	return field.TextFieldConfiguration{
		ID:     fieldIDFixNotPlannedNote,
		Prompt: "Note: ",
		RequestParamsUpdater: func(value string, p advisory.RequestParams) advisory.RequestParams {
			p.Note = value
			return p
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
		RequestParamsUpdater: func(value string, p advisory.RequestParams) advisory.RequestParams {
			p.Note = value
			return p
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
		RequestParamsUpdater: func(value string, p advisory.RequestParams) advisory.RequestParams {
			p.Note = value
			return p
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
		RequestParamsUpdater: func(value string, p advisory.RequestParams) advisory.RequestParams {
			p.FalsePositiveNote = value
			return p
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
		RequestParamsUpdater: func(value string, p advisory.RequestParams) advisory.RequestParams {
			p.FalsePositiveType = value
			return p
		},
	}
}

func (m Model) newFixedVersionFieldConfig(packageName string) (field.TextFieldConfiguration, error) {
	allowedVersions, err := m.allowedFixedVersionsFunc(packageName)
	if err != nil {
		return field.TextFieldConfiguration{}, fmt.Errorf("getting list of allowed fixed versions: %w", err)
	}

	cfg := field.TextFieldConfiguration{
		ID:     fieldIDFixedVersion,
		Prompt: "Fixed Version: ",
		RequestParamsUpdater: func(value string, p advisory.RequestParams) advisory.RequestParams {
			p.FixedVersion = value
			return p
		},
		AllowedValues:  allowedVersions,
		NoMatchHelpMsg: "No matching version found.",
	}

	if len(allowedVersions) >= 1 {
		cfg.DefaultSuggestion = allowedVersions[0]
	}

	return cfg, nil
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
	RequestParams              advisory.RequestParams
	AllowedPackagesFunc        func() ([]string, error)
	AllowedVulnerabilitiesFunc func(packageName string) ([]string, error)
	AllowedFixedVersionsFunc   func(packageName string) ([]string, error)
}

func New(config Configuration) Model {
	m := Model{
		RequestParams: config.RequestParams,

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
	if len(m.RequestParams.PackageNames) == 0 {
		fieldConfig, err := m.newPackageFieldConfig()
		if err != nil {
			m.Err = fmt.Errorf("failed to create package field: %w", err)
			m.EarlyExit = true
			return m, false
		}

		f := field.NewTextField(fieldConfig)
		m.fields = append(m.fields, f)
		return m, true
	}

	if len(m.RequestParams.Vulns) == 0 {
		fieldConfig, err := m.newVulnerabilityFieldConfig()
		if err != nil {
			m.Err = fmt.Errorf("failed to create vulnerability field: %w", err)
			m.EarlyExit = true
			return m, false
		}

		f := field.NewTextField(fieldConfig)
		m.fields = append(m.fields, f)
		return m, true
	}

	if m.RequestParams.EventType == "" {
		f := field.NewListField(m.newTypeFieldConfig())
		m.fields = append(m.fields, f)
		return m, true
	}

	switch p := m.RequestParams; p.EventType {
	case v2.EventTypeFixed:
		if p.FixedVersion == "" {
			if len(p.PackageNames) > 1 {
				m.Err = errors.New("prompting doesn't support fixed events when specifying multiple packages")
				m.EarlyExit = true
				return m, false
			}

			fieldConfig, err := m.newFixedVersionFieldConfig(p.PackageNames[0])
			if err != nil {
				m.Err = fmt.Errorf("failed to create fixed version field: %w", err)
				m.EarlyExit = true
				return m, false
			}

			f := field.NewTextField(fieldConfig)
			m.fields = append(m.fields, f)
			return m, true
		}

	case v2.EventTypeTruePositiveDetermination:
		// This field is optional. If we've already asked for it, don't ask again.
		if m.hasFieldWithID(fieldIDTruePositiveNote) {
			return m, false
		}

		if p.TruePositiveNote == "" && p.Note == "" {
			f := field.NewTextField(m.newTruePositiveNoteFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}

	case v2.EventTypeFalsePositiveDetermination:
		if p.FalsePositiveType == "" {
			f := field.NewListField(m.newFalsePositiveTypeFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}

		if p.FalsePositiveNote == "" && p.Note == "" {
			f := field.NewTextField(m.newFalsePositiveNoteFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}

	case v2.EventTypeFixNotPlanned:
		if p.Note == "" {
			f := field.NewTextField(m.newFixNotPlannedNoteFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}

	case v2.EventTypeAnalysisNotPlanned:
		if p.Note == "" {
			f := field.NewTextField(m.newAnalysisNotPlannedNoteFieldConfig())
			m.fields = append(m.fields, f)
			return m, true
		}

	case v2.EventTypePendingUpstreamFix:
		if p.Note == "" {
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

			m.RequestParams = sel.UpdateRequestParams(m.RequestParams)

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
