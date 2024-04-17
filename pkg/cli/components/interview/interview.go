package interview

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/picker"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/textinput"
	"github.com/wolfi-dev/wolfictl/pkg/question"
)

type Model[T any] struct {
	root                 question.Question[T]
	stack                []question.Question[T]
	answerComponentStack []tea.Model
	state                T
	done                 bool
}

// New returns a new interview model.
func New[T any](root question.Question[T], initialState T) Model[T] {
	m := Model[T]{
		root:  root,
		state: initialState,
	}

	m.stack = append(m.stack, root)

	ac := newAnswerComponent(root)
	m.answerComponentStack = append(m.answerComponentStack, ac)

	return m
}

func newAnswerComponent[T any](q question.Question[T]) tea.Model {
	switch a := q.Answer.(type) {
	case question.MultipleChoice[T]:
		opts := picker.Options[question.Choice[T]]{
			Items:          a,
			ItemRenderFunc: renderChoice[T],
		}
		return picker.New(opts)

	case question.AcceptText[T]:
		return textinput.New()
	}

	// This should never happen.
	panic("unsupported question answer type")
}

func (m Model[T]) stackTopIndex() int {
	return len(m.stack) - 1
}

func (m Model[T]) answerComponentStackTop() tea.Model {
	return m.answerComponentStack[m.stackTopIndex()]
}

func (m Model[T]) Init() tea.Cmd {
	return m.answerComponentStackTop().Init()
}

func (m Model[T]) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Most events should be routed to the component for the current question.

	switch m.answerComponentStackTop().(type) {
	case picker.Model[question.Choice[T]]:
		return m.updateForPicker(msg)

	case textinput.Model:
		return m.updateForTextInput(msg)
	}

	return m, nil
}

func (m Model[T]) updateForTextInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			// The user has submitted a text answer.
			// Update the state.
			val := m.answerComponentStackTop().(textinput.Model).Inner.Value()

			// Update the state.
			var nextQuestion *question.Question[T]
			m.state, nextQuestion = m.stack[m.stackTopIndex()].Answer.(question.AcceptText[T])(m.state, val)
			if nextQuestion == nil {
				// The line of questioning is concluded.
				m.done = true
				return m, tea.Quit
			}

			// The line of questioning continues.
			// Update the stack.
			m.stack = append(m.stack, *nextQuestion)

			// Create a new answer component for the next question.
			ac := newAnswerComponent(*nextQuestion)
			m.answerComponentStack = append(m.answerComponentStack, ac)

			return m, ac.Init()

		default:
			return m.routeMsgToTextInputAtTopOfStack(msg)
		}

	default:
		return m.routeMsgToTextInputAtTopOfStack(msg)
	}
}

func (m Model[T]) routeMsgToTextInputAtTopOfStack(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Pass the message to the text input.
	tiTea, cmd := m.answerComponentStackTop().Update(msg)
	ti, ok := tiTea.(textinput.Model)
	if !ok {
		// Nothing we can do here, but this shouldn't ever happen.
		return m, nil
	}

	m.answerComponentStack[m.stackTopIndex()] = ti
	return m, cmd
}

func (m Model[T]) updateForPicker(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter", "up", "down":
			pTea, cmd := m.answerComponentStackTop().Update(msg)
			p, ok := pTea.(picker.Model[question.Choice[T]])
			if !ok {
				// Nothing we can do here, but this shouldn't ever happen.
				return m, nil
			}
			m.answerComponentStack[m.stackTopIndex()] = p

			// Check if the user has submitted an answer.

			c := p.Picked()
			if c == nil {
				// The user hasn't picked an answer yet.
				return m, cmd
			}

			// The user has picked an answer.

			if c.Choose == nil {
				return m, nil
			}

			// Update the state.
			var nextQuestion *question.Question[T]
			m.state, nextQuestion = c.Choose(m.state)
			if nextQuestion == nil {
				// The line of questioning is concluded.
				m.done = true
				return m, tea.Quit
			}

			// The line of questioning continues.
			// Update the stack.
			m.stack = append(m.stack, *nextQuestion)

			// Create a new answer component for the next question.
			ac := newAnswerComponent(*nextQuestion)
			m.answerComponentStack = append(m.answerComponentStack, ac)

			return m, ac.Init()
		}

	default:
		// Pass the message to the picker.
		pTea, cmd := m.answerComponentStackTop().Update(msg)
		p, ok := pTea.(picker.Model[question.Choice[T]])
		if !ok {
			// Nothing we can do here, but this shouldn't ever happen.
			return m, nil
		}
		m.answerComponentStack[m.stackTopIndex()] = p
		return m, cmd
	}

	return m, nil
}

func (m Model[T]) View() string {
	// TODO: consider rendering differently if m.done is true.

	sb := strings.Builder{}

	for i, q := range m.stack {
		sb.WriteString(q.Text + "\n\n")

		acView := m.answerComponentStack[i].View()
		sb.WriteString(acView)
	}

	return sb.String()
}

func (m Model[T]) State() T {
	return m.state
}

func renderChoice[T any](c question.Choice[T]) string {
	return c.Text
}
