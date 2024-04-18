package question

import "errors"

type Question[T any] struct {
	// The question to ask the user.
	Text string

	// The means of answering the question. The concrete type should be one of:
	// - AcceptText[T]
	// - MessageOnly[T]
	// - MultipleChoice[T]
	Answer any
}

// MultipleChoice is a means of answering a question where the user can choose
// an option (Choice) from a list.
type MultipleChoice[T any] []Choice[T]

type Choice[T any] struct {
	// The Text of the choice to present to the user.
	Text string

	// Choose should update and return the given state in consideration of this
	// choice being selected by the user. It can also return the next question,
	// unless the line of questioning is concluded, in which case it should return
	// nil.
	Choose ChooseFunc[T]
}

// ChooseFunc is a function that can be used as the Choose method of a Choice.
type ChooseFunc[T any] func(state T) (updated T, next *Question[T], err error)

// NewChooseFunc returns a function that can be used as the Choose method of a
// Choice. It simply returns the state unmodified and the given next question.
func NewChooseFunc[T any](next *Question[T]) ChooseFunc[T] {
	return func(state T) (T, *Question[T], error) {
		return state, next, nil
	}
}

// AcceptText is a means of answering a question where the user can provide
// freeform text.
type AcceptText[T any] func(state T, text string) (T, *Question[T], error)

// MessageOnly is a means of answering a question where the user is presented
// with a message only, and where the only possible action is to proceed to the
// next question.
//
// In other words, this effectively turns the Question into a message that the
// user must acknowledge before proceeding.
type MessageOnly[T any] func(state T) (T, *Question[T], error)

// NewMessage returns a new "Question" that is only a message for the user to
// acknowledge. Once acknowledged, the user will proceed to the supplied next
// question, and the state will be passed through unmodified.
func NewMessage[T any](text string, next *Question[T]) Question[T] {
	return Question[T]{
		Text: text,
		Answer: MessageOnly[T](func(state T) (T, *Question[T], error) {
			return state, next, nil
		}),
	}
}

// NewTerminatingMessage returns a new "Question" that is only a message for the
// user to acknowledge. Once acknowledged, the interview should terminate.
func NewTerminatingMessage[T any](text string) Question[T] {
	return Question[T]{
		Text: text,
		Answer: MessageOnly[T](func(state T) (T, *Question[T], error) {
			return state, nil, ErrTerminate
		}),
	}
}

var (
	// ErrTerminate is a sentinel error an answer function can return to indicate
	// that the interview should terminate, and the tracked state should be
	// discarded rather than persisted or returned to the user.
	ErrTerminate = errors.New("interview terminated")
)
