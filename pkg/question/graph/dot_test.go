package graph

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/wolfi-dev/wolfictl/pkg/question"
)

func TestDot(t *testing.T) {
	var (
		qIcecreamFlavor = question.Question[string]{
			Text: "What flavor of ice cream do you like?",
			Choices: []question.Choice[string]{
				{
					Text: "Vanilla",
					Choose: func(state string) (string, *question.Question[string]) {
						return "vanilla " + state, nil
					},
				},
				{
					Text: "Chocolate",
					Choose: func(state string) (string, *question.Question[string]) {
						return "chocolate " + state, nil
					},
				},
			},
		}

		qCookieKind = question.Question[string]{
			Text: "What kind of cookie do you like?",
			Choices: []question.Choice[string]{
				{
					Text: "Chocolate chip",
					Choose: func(state string) (string, *question.Question[string]) {
						return "chocolate chip " + state, nil
					},
				},
			},
		}

		qFavoriteDessert = question.Question[string]{
			Text: "What is your favorite dessert?",
			Choices: []question.Choice[string]{
				{
					Text: "Ice cream",
					Choose: func(_ string) (string, *question.Question[string]) {
						return "ice cream", &qIcecreamFlavor
					},
				},
				{
					Text: "Cookie",
					Choose: func(_ string) (string, *question.Question[string]) {
						return "cookie", &qCookieKind
					},
				},
			},
		}
	)

	var (
		expected = `digraph interview {
Done;
"What is your favorite dessert?";
"What flavor of ice cream do you like?";
"What is your favorite dessert?" -> "What flavor of ice cream do you like?"  [ label="Ice cream" ]
"What flavor of ice cream do you like?" -> Done  [ label=Vanilla ]
"What flavor of ice cream do you like?" -> Done  [ label=Chocolate ]
"What kind of cookie do you like?";
"What is your favorite dessert?" -> "What kind of cookie do you like?"  [ label=Cookie ]
"What kind of cookie do you like?" -> Done  [ label="Chocolate chip" ]
}
`
	)

	dot, err := Dot(context.Background(), qFavoriteDessert, "")
	if err != nil {
		t.Fatalf("Dot() error = %v", err)
	}

	if diff := cmp.Diff(expected, dot); diff != "" {
		t.Errorf("Dot() unexpected output (-want +got):\n%s", diff)
	}
}
