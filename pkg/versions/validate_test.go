package versions

import "testing"

func TestValidateWithoutEpoch(t *testing.T) {
	cases := []struct {
		v             string
		shouldBeValid bool
	}{
		// These are all valid versions.
		{"1", true},
		{"1.0", true},
		{"1.0.0", true},
		{"3000.200.10", true},
		{"1.0.0_alpha", true},
		{"1.0.0-r100000000000000000", true},
		{"1.2.3.4.5.6.7.8.9", true},
		{"1.0.0z_p", true},
		{"1.0.0_p5", true},
		{"1.2.2_git20230928", true},

		// Yes, this is valid, and the "-r0" is NOT the epoch here. 🤯
		{"1.0.0-r0", true},

		// These are all invalid versions.
		{"1.0.0-alpha", false},
		{"1.0.0_alpha.1", false},
		{"1.0.0\n2.0.0", false},
		{"1.0.0nevergonnagiveyouu_p", false},
		{"pre-1.0.0", false},
		{"jenkins-7", false},
		{"1.0.0 ", false},
		{"1_0", false},
	}

	for _, tt := range cases {
		t.Run(tt.v, func(t *testing.T) {
			err := ValidateWithoutEpoch(tt.v)
			if tt.shouldBeValid && err != nil {
				t.Errorf("expected %q to be valid, but got error %q", tt.v, err)
			}
			if !tt.shouldBeValid && err == nil {
				t.Errorf("expected %q to be invalid, but got no error", tt.v)
			}
		})
	}
}

func TestValidateWithEpoch(t *testing.T) {
	cases := []struct {
		v             string
		shouldBeValid bool
	}{
		// These are all valid full versions.
		{"1-r0", true},
		{"1.0-r0", true},
		{"1.0.0-r0", true},
		{"1.0.0-r4-r5", true},
		{"1.0.0_alpha-r0", true},
		{"1.0.0-r100000000000000000", true},

		// These are all invalid full versions.
		{"1.0.0", false},
		{"1.0.0-r5.2", false},
		{"1.0.0-r5_pre", false},
		{"1r6", false},
		{"1.0.0-r", false},
		{"1.0-r1-r2-r3", false},
	}

	for _, tt := range cases {
		t.Run(tt.v, func(t *testing.T) {
			err := ValidateWithEpoch(tt.v)
			if tt.shouldBeValid && err != nil {
				t.Errorf("expected %q to be valid, but got error %q", tt.v, err)
			}
			if !tt.shouldBeValid && err == nil {
				t.Errorf("expected %q to be invalid, but got no error", tt.v)
			}
		})
	}
}
