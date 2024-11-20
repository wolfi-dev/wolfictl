package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequest_Validate(t *testing.T) {
	tests := []struct {
		name           string
		req            Request
		errorAssertion assert.ErrorAssertionFunc
	}{
		{
			name: "empty package",
			req: Request{
				Package: "",
			},
			errorAssertion: func(t assert.TestingT, err error, _ ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrEmptyPackage)
			},
		},
		{
			name: "invalid advisory ID",
			req: Request{
				Package:    "foo",
				AdvisoryID: "foo",
			},
			errorAssertion: func(t assert.TestingT, err error, _ ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrInvalidAdvisoryID)
			},
		},
		{
			name: "alias with invalid vulnerability ID",
			req: Request{
				Package: "foo",
				Aliases: []string{"foo", "bar", "baz"},
			},
			errorAssertion: func(t assert.TestingT, err error, _ ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrInvalidVulnerabilityID)
			},
		},
		{
			name: "CGA ID as alias",
			req: Request{
				Package: "foo",
				Aliases: []string{"CGA-xxxx-xxxx-xxxx"},
			},
			errorAssertion: func(t assert.TestingT, err error, _ ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrCGAIDAsAlias)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.errorAssertion(t, tt.req.Validate())
		})
	}
}
