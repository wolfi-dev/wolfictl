package field

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
)

var (
	selectedSuggestionStyle = styles.Accented().Copy().Underline(true)
	helpKeyStyle            = styles.FaintAccent().Copy().Bold(true)
	helpExplanationStyle    = styles.Faint().Copy()
)

const maxSuggestionsDisplayed = 4

var ErrValueNotInAllowedSet = errors.New("value not in allowed set")

type TextField struct {
	id             string
	allowedValues  []string
	requestUpdater func(value string, req advisory.Request) advisory.Request

	input                 textinput.Model
	done                  bool
	currentSuggestions    []string
	selectedSuggestion    int
	suggestionWindowStart int
	defaultSuggestion     string
	validationRules       []TextValidationRule
	currentValidationErr  error

	emptyValueHelpMsg string
	noMatchHelpMsg    string
}

type TextFieldConfiguration struct {
	// ID is a unique identifier for the field.
	ID string

	// Prompt is the text shown before the input field. (E.g. "Name: ")
	Prompt string

	// RequestUpdater is a function that updates the advisory request with the
	// current field value.
	RequestUpdater func(value string, req advisory.Request) advisory.Request

	// AllowedValues is a list of values that are allowed to be entered and are used
	// as suggestions when the user starts typing.
	AllowedValues []string

	// DefaultSuggestion is the value that is shown as a suggestion when the user
	// hasn't entered anything.
	DefaultSuggestion string

	// EmptyValueHelpMsg is the help message shown when the user hasn't entered
	// anything and there are no suggestions.
	EmptyValueHelpMsg string

	// NoMatchHelpMsg is the help message shown when the user has entered something
	// but there are no matching suggestions.
	NoMatchHelpMsg string

	// ValidationRules is a list of validation rules that are run when the user
	// submits the field. All rules must pass for the field to be valid.
	ValidationRules []TextValidationRule
}

type TextValidationRule func(string) error

func NewTextField(cfg TextFieldConfiguration) TextField {
	t := textinput.New()
	t.Cursor.Style = styles.Default()

	t.Prompt = cfg.Prompt

	return TextField{
		id:                cfg.ID,
		input:             t,
		requestUpdater:    cfg.RequestUpdater,
		allowedValues:     cfg.AllowedValues,
		emptyValueHelpMsg: cfg.EmptyValueHelpMsg,
		noMatchHelpMsg:    cfg.NoMatchHelpMsg,
		validationRules:   cfg.ValidationRules,
		defaultSuggestion: cfg.DefaultSuggestion,
	}
}

func NotEmpty(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("cannot be empty")
	}

	return nil
}

func (f TextField) ID() string {
	return f.id
}

func (f TextField) runAllValidationRules(value string) error {
	for _, rule := range f.validationRules {
		err := rule(value)
		if err != nil {
			return err
		}
	}

	return nil
}

func (f TextField) UpdateRequest(req advisory.Request) advisory.Request {
	value := f.Value()
	return f.requestUpdater(value, req)
}

func (f TextField) SubmitValue() (Field, error) {
	if f.usingSuggestions() && f.noSuggestions() {
		return nil, ErrValueNotAccepted{
			Value:  f.input.Value(),
			Reason: ErrValueNotInAllowedSet,
		}
	}

	value := f.Value()

	err := f.runAllValidationRules(value)
	if err != nil {
		return nil, ErrValueNotAccepted{
			Value:  value,
			Reason: err,
		}
	}

	f = f.setDone()

	return f, nil
}

func (f TextField) Update(msg tea.Msg) (Field, tea.Cmd) {
	if f.done {
		return f, nil
	}

	m, cmd := f.input.Update(msg)
	f.input = m

	f.currentValidationErr = f.runAllValidationRules(f.input.Value())

	if !f.usingSuggestions() {
		return f, cmd
	}

	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.String() {
		case "tab":
			f = f.nextSuggestion()

		case "shift+tab":
			f = f.previousSuggestion()

		default:
			f = f.updateSuggestions()
		}
	}

	return f, cmd
}

func (f TextField) usingSuggestions() bool {
	return f.allowedValues != nil
}

func (f TextField) updateSuggestions() TextField {
	f.currentSuggestions = f.computeSuggestions()
	f.selectedSuggestion = 0
	f.suggestionWindowStart = 0

	return f
}

func (f TextField) nextSuggestion() TextField {
	if f.selectedSuggestion == len(f.currentSuggestions)-1 {
		return f
	}

	if f.selectedSuggestion == f.suggestionWindowEnd()-1 {
		f.suggestionWindowStart++
	}

	f.selectedSuggestion++
	return f
}

func (f TextField) previousSuggestion() TextField {
	if f.selectedSuggestion == 0 {
		return f
	}

	if f.selectedSuggestion == f.suggestionWindowStart {
		f.suggestionWindowStart--
	}

	f.selectedSuggestion--
	return f
}

func (f TextField) computeSuggestions() []string {
	v := f.input.Value()

	if v == "" {
		if f.defaultSuggestion != "" {
			return []string{f.defaultSuggestion}
		}

		return nil
	}

	var suggestions []string

	for _, allowedValue := range f.allowedValues {
		if strings.HasPrefix(allowedValue, v) {
			suggestions = append(suggestions, allowedValue)
		}
	}

	return suggestions
}

func (f TextField) suggestionWindowEnd() int {
	if len(f.currentSuggestions) <= maxSuggestionsDisplayed {
		return len(f.currentSuggestions)
	}

	return f.suggestionWindowStart + maxSuggestionsDisplayed
}

func (f TextField) setDone() TextField {
	f.done = true
	return f
}

func (f TextField) SetBlur() Field {
	f.input.Blur()

	f.input.PromptStyle = styles.Default()
	f.input.TextStyle = styles.Default()

	return f
}

func (f TextField) SetFocus() (Field, tea.Cmd) {
	cmd := f.input.Focus()

	f = f.updateSuggestions()
	f.input.PromptStyle = styles.Default()
	f.input.TextStyle = styles.Default()

	return f, cmd
}

func (f TextField) IsDone() bool {
	return f.done
}

func (f TextField) Value() string {
	if !f.usingSuggestions() {
		return f.input.Value()
	}

	selectedValue := f.currentSuggestions[f.selectedSuggestion]
	return selectedValue
}

func (f TextField) View() string {
	var lines []string

	if f.done && f.usingSuggestions() {
		f.input.SetValue(f.Value())
	}

	inputLine := f.input.View()

	if !f.done && f.usingSuggestions() {
		inputLine = fmt.Sprintf("%s   %s", inputLine, f.renderSuggestions())
	}

	lines = append(lines, inputLine)

	if !f.done {
		helpText := f.renderHelp()
		lines = append(lines, helpText)
	}

	return strings.Join(lines, "\n")
}

func (f TextField) noSuggestions() bool {
	return len(f.currentSuggestions) == 0
}

func (f TextField) onlyOneSuggestion() bool {
	return len(f.currentSuggestions) == 1
}

func (f TextField) multipleSuggestions() bool {
	return len(f.currentSuggestions) > 1
}

func (f TextField) userHasEnteredText() bool {
	return f.input.Value() != ""
}

func (f TextField) enteredTextIsSoleSuggestion() bool {
	return f.input.Value() == f.currentSuggestions[0]
}

func (f TextField) enteredValueIsValid() bool {
	return f.currentValidationErr == nil
}

func (f TextField) renderSuggestions() string {
	if !f.userHasEnteredText() && f.defaultSuggestion != "" {
		return selectedSuggestionStyle.Render(f.defaultSuggestion)
	}

	if f.noSuggestions() || (f.onlyOneSuggestion() && f.enteredTextIsSoleSuggestion()) {
		return ""
	}

	renderedSuggestions := make([]string, 0, maxSuggestionsDisplayed)

	for i := f.suggestionWindowStart; i < f.suggestionWindowEnd(); i++ {
		suggestion := f.currentSuggestions[i]
		if i == f.selectedSuggestion {
			suggestion = selectedSuggestionStyle.Render(suggestion)
		} else {
			suggestion = styles.Secondary().Render(suggestion)
		}
		renderedSuggestions = append(renderedSuggestions, suggestion)
	}

	ellipses := styles.Secondary().Render("…")

	if f.suggestionWindowStart > 0 {
		renderedSuggestions = append([]string{ellipses}, renderedSuggestions...)
	}

	if f.suggestionWindowEnd() < len(f.currentSuggestions) {
		renderedSuggestions = append(renderedSuggestions, ellipses)
	}

	return strings.Join(renderedSuggestions, " ")
}

func (f TextField) renderHelp() string {
	var helpMsgs []string

	if msg := f.renderHelpMsgEmptyValue(); !f.userHasEnteredText() && msg != "" {
		helpMsgs = append(helpMsgs, msg)
	} else if !f.enteredValueIsValid() {
		msg := styles.Faint().Render(
			fmt.Sprintf("Invalid value: %s.", f.currentValidationErr),
		)
		helpMsgs = append(helpMsgs, msg)
	}

	if f.usingSuggestions() {
		switch {
		case f.noSuggestions() && f.userHasEnteredText():
			helpMsgs = append(helpMsgs, f.renderHelpMsgNoMatch())

		case f.onlyOneSuggestion() && f.enteredTextIsSoleSuggestion():
			helpMsgs = append(helpMsgs, helpMsgEnterOnInput)

		case f.onlyOneSuggestion() && !f.enteredTextIsSoleSuggestion():
			helpMsgs = append(helpMsgs, helpMsgEnterOnSuggestion)

		case f.multipleSuggestions():
			helpMsgs = append(helpMsgs, helpMsgEnterOnSuggestion, helpMsgTab)
		}
	} else if f.userHasEnteredText() && f.enteredValueIsValid() {
		helpMsgs = append(helpMsgs, helpMsgEnterOnInput)
	}

	helpMsgs = append(helpMsgs, helpMsgQuit)
	return strings.Join(helpMsgs, " ")
}

func (f TextField) renderHelpMsgEmptyValue() string {
	msg := f.emptyValueHelpMsg
	if msg == "" {
		return ""
	}

	return styles.Faint().Render(msg)
}

func (f TextField) renderHelpMsgNoMatch() string {
	return styles.Faint().Render(f.noMatchHelpMsg)
}

var (
	helpMsgEnterOnInput      = helpKeyStyle.Render("Enter") + " " + helpExplanationStyle.Render("to confirm.")
	helpMsgEnterOnSuggestion = helpKeyStyle.Render("Enter") + " " + helpExplanationStyle.Render("to accept suggestion.")
	helpMsgTab               = helpKeyStyle.Render("Tab") + " " + helpExplanationStyle.Render("for next suggestion.")
	helpMsgQuit              = helpKeyStyle.Render("Ctrl+C") + " " + helpExplanationStyle.Render("to quit.")
)
