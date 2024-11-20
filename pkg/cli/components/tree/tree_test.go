package tree

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestTree_Render(t *testing.T) {
	tests := []struct {
		name       string
		leaves     []string
		renderFunc func(leaf string) []string
		want       string
	}{
		{
			name:       "empty tree",
			renderFunc: NewStringSplitRenderFunc(""),
			want:       "",
		},
		{
			name:       "single leaf",
			leaves:     []string{"A"},
			renderFunc: NewStringSplitRenderFunc(""),
			want:       "A\n",
		},
		{
			name:       "two leaves",
			leaves:     []string{"A", "B"},
			renderFunc: NewStringSplitRenderFunc(""),
			want: `A
B
`,
		},
		{
			name:       "two leaves with common prefix",
			leaves:     []string{"A/B", "A/C"},
			renderFunc: NewStringSplitRenderFunc("/"),
			want: `A
├── B
└── C
`,
		},
		{
			name:       "three leaves with common prefix",
			leaves:     []string{"A/B/C", "A/B/D", "A/C"},
			renderFunc: NewStringSplitRenderFunc("/"),
			want: `A
├── B
│       C
│       D
└── C
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := New(tt.leaves, tt.renderFunc)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			got := tree.Render()

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Render() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
