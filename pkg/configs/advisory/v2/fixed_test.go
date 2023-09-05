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
		f := Fixed{}
		if err := f.Validate(); err == nil {
			t.Errorf("expected error, got nil")
		}
	})
}
