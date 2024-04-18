package question

type Question[T any] struct {
	// The question to ask the user.
	Text string

	// The means of answering the question. The concrete type should be one of:
	// - AcceptText[T]
	// - MultipleChoice[T]
	Answer any
}

type MultipleChoice[T any] []Choice[T]

type AcceptText[T any] func(state T, text string) (T, *Question[T])

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
type ChooseFunc[T any] func(state T) (updated T, next *Question[T])

// NewChooseFunc returns a function that can be used as the Choose method of a
// Choice. It simply returns the state unmodified and the given next question.
func NewChooseFunc[T any](next *Question[T]) ChooseFunc[T] {
	return func(state T) (T, *Question[T]) {
		return state, next
	}
}
