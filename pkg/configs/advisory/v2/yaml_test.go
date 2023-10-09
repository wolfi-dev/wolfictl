package v2

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func Test_strictUnmarshal(t *testing.T) {
	type targetDataType struct {
		Color string `yaml:"color"`
	}

	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{
			name:    "empty",
			in:      "",
			wantErr: false,
		},
		{
			name:    "complete",
			in:      "color: blue",
			wantErr: false,
		},
		{
			name:    "invalid due to unknown fields",
			in:      "color: blue\nextra: field",
			wantErr: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			n := new(yaml.Node)
			err := yaml.Unmarshal([]byte(tt.in), n)
			if err != nil {
				t.Fatalf("failed to decode test YAML data: %v", err)
			}

			v, err := strictUnmarshal[targetDataType](n)
			if (err != nil) != tt.wantErr {
				t.Errorf("strictUnmarshal() error = %v, wantErr %v, actual value was %+v", err, tt.wantErr, v)
				return
			}
		})
	}
}
