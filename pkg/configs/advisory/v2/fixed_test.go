package v2

import "testing"

func TestFixed_Validate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		f := Fixed{
			FixedVersion: "1.2.3-r4",
		}
		if err := f.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		cases := []struct {
			name string
			f    Fixed
		}{
			{
				name: "empty",
				f:    Fixed{},
			},
			{
				name: "missing epoch",
				f: Fixed{
					FixedVersion: "1.2.3",
				},
			},
		}

		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				if err := tt.f.Validate(); err == nil {
					t.Errorf("expected error, got nil")
				}
			})
		}
	})
}
