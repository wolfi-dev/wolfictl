package interview

import (
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/accept"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/picker"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/textinput"
	"github.com/wolfi-dev/wolfictl/pkg/cli/internal/wrapped"
	"github.com/wolfi-dev/wolfictl/pkg/question"
)

type Model[T any] struct {
	root                 question.Question[T]
	stack                []question.Question[T]
	answerComponentStack []tea.Model
	state                T
	done                 bool
	err                  error
}

// New returns a new interview model.
func New[T any](root question.Question[T], initialState T) (Model[T], error) {
	m := Model[T]{
		root:  root,
		state: initialState,
	}

	m.stack = append(m.stack, root)

	ac, err := newAnswerComponent(root)
	if err != nil {
		return m, fmt.Errorf("creating answer component: %w", err)
	}
	m.answerComponentStack = append(m.answerComponentStack, ac)

	return m, nil
}

func newAnswerComponent[T any](q question.Question[T]) (tea.Model, error) {
	switch a := q.Answer.(type) {
	case question.MultipleChoice[T]:
		opts := picker.Options[question.Choice[T]]{
			Items:          a,
			ItemRenderFunc: renderChoice[T],
		}
		return picker.New(opts), nil

	case question.AcceptText[T]:
		return textinput.New(), nil

	case question.MessageOnly[T]:
		return accept.Model{}, nil
	}

	// This should never happen.
	return nil, fmt.Errorf("unsupported question answer type %T for question %q", q.Answer, q.Text)
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

	case accept.Model:
		return m.updateForMessage(msg)
	}

	return m, nil
}

func (m Model[T]) updateForMessage(msg tea.Msg) (tea.Model, tea.Cmd) {
	messageTea, cmd := m.answerComponentStackTop().Update(msg)
	messageModel, ok := messageTea.(accept.Model)
	if !ok {
		// Nothing we can do here, but this shouldn't ever happen.
		return m, nil
	}
	m.answerComponentStack[m.stackTopIndex()] = messageModel

	if !messageModel.Accepted {
		// The user hasn't acknowledged the message yet.
		return m, cmd
	}

	// The user has acknowledged the message.

	// Update the state.
	var nextQuestion *question.Question[T]
	var err error
	m.state, nextQuestion, err = m.stack[m.stackTopIndex()].Answer.(question.MessageOnly[T])(m.state)
	if err != nil {
		if errors.Is(err, question.ErrTerminate) {
			// Exit the interview without a resulting state.
			m.done = true
			m.err = err
			return m, tea.Quit
		}

		// An error occurred.
		m.err = err
		return m, tea.Quit
	}

	if nextQuestion == nil {
		// The line of questioning is concluded.
		m.done = true
		return m, tea.Quit
	}

	// The line of questioning continues.
	// Update the stack.
	m.stack = append(m.stack, *nextQuestion)

	// Create a new answer component for the next question.
	ac, err := newAnswerComponent(*nextQuestion)
	if err != nil {
		// An error occurred.
		m.err = err
		return m, tea.Quit
	}
	m.answerComponentStack = append(m.answerComponentStack, ac)

	return m, ac.Init()
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
			var err error
			m.state, nextQuestion, err = m.stack[m.stackTopIndex()].Answer.(question.AcceptText[T])(m.state, val)
			if err != nil {
				if errors.Is(err, question.ErrTerminate) {
					// Exit the interview without a resulting state.
					m.done = true
					m.err = err
					return m, tea.Quit
				}

				// An error occurred.
				m.err = err
				return m, tea.Quit
			}
			if nextQuestion == nil {
				// The line of questioning is concluded.
				m.done = true
				return m, tea.Quit
			}

			// The line of questioning continues.
			// Update the stack.
			m.stack = append(m.stack, *nextQuestion)

			// Create a new answer component for the next question.
			ac, err := newAnswerComponent(*nextQuestion)
			if err != nil {
				// An error occurred.
				m.err = err
				return m, tea.Quit
			}
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
			var err error
			m.state, nextQuestion, err = c.Choose(m.state)
			if err != nil {
				if errors.Is(err, question.ErrTerminate) {
					// Exit the interview without a resulting state.
					m.done = true
					m.err = err
					return m, tea.Quit
				}

				// An error occurred.
				m.err = err
				return m, tea.Quit
			}
			if nextQuestion == nil {
				// The line of questioning is concluded.
				m.done = true
				return m, tea.Quit
			}

			// The line of questioning continues.
			// Update the stack.
			m.stack = append(m.stack, *nextQuestion)

			// Create a new answer component for the next question.
			ac, err := newAnswerComponent(*nextQuestion)
			if err != nil {
				// An error occurred.
				m.err = err
				return m, tea.Quit
			}
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
		qText := wrapped.Sprint(q.Text)
		sb.WriteString(qText + "\n\n")

		acView := m.answerComponentStack[i].View()
		sb.WriteString(acView)
	}

	return sb.String()
}

func (m Model[T]) State() (T, error) {
	return m.state, m.err
}

func renderChoice[T any](c question.Choice[T]) string {
	return c.Text
}
