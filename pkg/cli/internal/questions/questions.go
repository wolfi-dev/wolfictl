package questions

type Question[T any] struct {
	// The question to ask the user.
	Text string

	// Choices is a list of possible answers to the question.
	Choices []Choice[T]
}

type Choice[T any] struct {
	// The Text of the choice to present to the user.
	Text string

	// Choose should update and return the given state in consideration of this
	// choice being selected by the user. It can also return the next question,
	// unless the line of questioning is concluded, in which case it should return
	// nil.
	Choose func(state T) (updated T, next *Question[T])
}
