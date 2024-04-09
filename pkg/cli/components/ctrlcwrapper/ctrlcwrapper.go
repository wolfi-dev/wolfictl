package ctrlcwrapper

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type Model[T tea.Model] struct {
	userWantsToExit bool

	inner T
}

// Any is a type that can be used to check if a model is a Model
// without knowing the inner type.
type Any interface {
	UserWantsToExit() bool
}

type AboutToExitMsg struct{}

// InnerIsReady is a tea.Cmd that the inner model can send to the wrapper model
// to indicate that it's ready to exit. This is helpful to the overall program
// because it allows the wrapper to exit earlier than it would if it waited for
// its own internal tick expiration event.
func InnerIsReady() tea.Msg {
	return innerIsReadyMsg{}
}

type innerIsReadyMsg struct{}

type tickExpiredMsg struct{}

// New returns a new model that wraps the given model. The new model will exit
// when the user presses Ctrl+C.
func New[T tea.Model](inner T) tea.Model {
	return Model[T]{
		inner: inner,
	}
}

// Unwrap returns the inner model with its original type.
func (m Model[T]) Unwrap() T {
	return m.inner
}

// UserWantsToExit returns true if the user pressed Ctrl+C. This can be used
// when the bubbletea program exits to determine if the user wants to exit the
// program.
func (m Model[T]) UserWantsToExit() bool {
	return m.userWantsToExit
}

func (m Model[T]) Init() tea.Cmd {
	return m.inner.Init()
}

func (m Model[T]) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.userWantsToExit = true

			// Tell the inner model that we're about to exit. Cmds aren't supported
			// currently.
			updated, _ := m.inner.Update(AboutToExitMsg{})
			var inner T
			var ok bool
			if inner, ok = updated.(T); !ok {
				// Nothing we can do here, but this shouldn't ever happen.
				return m, nil
			}

			m.inner = inner

			// We'll give the inner model a second to clean up before we exit. This is like
			// a SIGINT.
			delayedExitCmd := tea.Tick(1*time.Second, func(time.Time) tea.Msg {
				return tickExpiredMsg{}
			})

			return m, delayedExitCmd
		}

	case innerIsReadyMsg, tickExpiredMsg:
		// The inner has finished its cleanup and is ready to exit.
		// Or, the "SIGINT" delay has expired, so we're going to exit anyway!
		return m, tea.Quit
	}

	// Normal proxying of messages to the inner model.
	updated, cmd := m.inner.Update(msg)
	var inner T
	var ok bool
	if inner, ok = updated.(T); !ok {
		// Nothing we can do here, but this shouldn't ever happen.
		return m, nil
	}

	m.inner = inner

	return m, cmd
}

func (m Model[T]) View() string {
	return m.inner.View()
}
