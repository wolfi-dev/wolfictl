package interview

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/picker"
	"github.com/wolfi-dev/wolfictl/pkg/question"
)

type Model[T any] struct {
	root        question.Question[T]
	stack       []question.Question[T]
	pickerStack []picker.Model[question.Choice[T]]
	state       T
	done        bool
}

// New returns a new interview model.
func New[T any](root question.Question[T], initialState T) Model[T] {
	m := Model[T]{
		root:  root,
		state: initialState,
	}

	pickerOpts := picker.Options[question.Choice[T]]{
		Items:          root.Choices,
		ItemRenderFunc: renderChoice[T],
	}
	p := picker.New(pickerOpts)
	m.stack = append(m.stack, root)
	m.pickerStack = append(m.pickerStack, p)

	return m
}

func (m Model[T]) stackTopIndex() int {
	return len(m.stack) - 1
}

func (m Model[T]) pickerStackTop() picker.Model[question.Choice[T]] {
	return m.pickerStack[m.stackTopIndex()]
}

func (m Model[T]) Init() tea.Cmd {
	return m.pickerStackTop().Init()
}

func (m Model[T]) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Most events should be routed to the picker for the current question.

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter", "up", "down":
			pTea, cmd := m.pickerStackTop().Update(msg)
			p, ok := pTea.(picker.Model[question.Choice[T]])
			if !ok {
				// Nothing we can do here, but this shouldn't ever happen.
				return m, nil
			}
			m.pickerStack[m.stackTopIndex()] = p

			// Check if the user has picked an answer.

			c := m.pickerStackTop().Picked()
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
			nextPickerOpts := picker.Options[question.Choice[T]]{
				Items:          nextQuestion.Choices,
				ItemRenderFunc: renderChoice[T],
			}
			nextPicker := picker.New(nextPickerOpts)
			m.pickerStack = append(m.pickerStack, nextPicker)

			return m, nextPicker.Init()
		}

	default:
		// Pass the message to the picker.
		pTea, cmd := m.pickerStackTop().Update(msg)
		p, ok := pTea.(picker.Model[question.Choice[T]])
		if !ok {
			// Nothing we can do here, but this shouldn't ever happen.
			return m, nil
		}
		m.pickerStack[m.stackTopIndex()] = p
		return m, cmd
	}

	return m, nil
}

func (m Model[T]) View() string {
	// TODO: consider rendering differently if m.done is true.

	sb := strings.Builder{}

	for i, q := range m.stack {
		sb.WriteString(q.Text + "\n\n")

		pickerView := m.pickerStack[i].View()
		sb.WriteString(pickerView)
	}

	return sb.String()
}

func (m Model[T]) State() T {
	return m.state
}

func renderChoice[T any](c question.Choice[T]) string {
	return c.Text
}
