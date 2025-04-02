package advisory

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
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

func TestRequestParams_MissingValues(t *testing.T) {
	cases := []struct {
		name      string
		reqParams RequestParams
		expected  []string
	}{
		{
			name:      "totally empty",
			reqParams: RequestParams{},
			expected: []string{
				RequestParamPackageNames,
				RequestParamVulns,
				RequestParamEventType,
				RequestParamTimestamp,
			},
		},
		{
			name: "have only vulns and event type of fixed",
			reqParams: RequestParams{
				Vulns:     []string{"CVE-2222-2222"},
				EventType: v2.EventTypeFixed,
			},
			expected: []string{
				RequestParamPackageNames,
				RequestParamTimestamp,
				RequestParamFixedVersion,
			},
		},
		{
			name: "have only package names, timestamp, and event type of false positive",
			reqParams: RequestParams{
				PackageNames: []string{"foo", "bar"},
				Timestamp:    "2023-01-01T00:00:00Z",
				EventType:    v2.EventTypeFalsePositiveDetermination,
			},
			expected: []string{
				RequestParamVulns,
				RequestParamFalsePositiveType,
				RequestParamFalsePositiveNote,
			},
		},
		{
			name: "false positive using generic note field (which is acceptable)",
			reqParams: RequestParams{
				PackageNames:      []string{"foo"},
				Vulns:             []string{"CVE-2222-2222"},
				EventType:         v2.EventTypeFalsePositiveDetermination,
				FalsePositiveType: v2.FPTypeVulnerabilityRecordAnalysisContested,
				Timestamp:         "now",
				Note:              "because because because because because",
			},
		},
		{
			name: "fix-not-planned without note",
			reqParams: RequestParams{
				PackageNames: []string{"foo"},
				Vulns:        []string{"CVE-2222-2222"},
				EventType:    v2.EventTypeFixNotPlanned,
				Timestamp:    "now",
			},
			expected: []string{
				RequestParamNote,
			},
		},
		{
			name: "fix-not-planned with note",
			reqParams: RequestParams{
				PackageNames: []string{"foo"},
				Vulns:        []string{"CVE-2222-2222"},
				EventType:    v2.EventTypeFixNotPlanned,
				Timestamp:    "now",
				Note:         "because because because because because",
			},
			expected: nil,
		},
		{
			name: "fixed with fixed version",
			reqParams: RequestParams{
				PackageNames: []string{"foo"},
				Vulns:        []string{"CVE-2222-2222"},
				EventType:    v2.EventTypeFixed,
				Timestamp:    "now",
				FixedVersion: "1.0.0-r0",
			},
			expected: nil,
		},
		{
			name: "true positive with note",
			reqParams: RequestParams{
				PackageNames: []string{"foo"},
				Vulns:        []string{"CVE-2222-2222"},
				EventType:    v2.EventTypeTruePositiveDetermination,
				Timestamp:    "now",
				Note:         "because because because because because",
			},
			expected: nil,
		},
		{
			name: "true positive without note",
			reqParams: RequestParams{
				PackageNames: []string{"foo"},
				Vulns:        []string{"CVE-2222-2222"},
				EventType:    v2.EventTypeTruePositiveDetermination,
				Timestamp:    "now",
			},
			expected: []string{
				RequestParamTruePositiveNote,
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.reqParams.MissingValues()

			if diff := cmp.Diff(tt.expected, actual); diff != "" {
				t.Errorf("RequestParams.MissingValues() mismatch (-expected +actual):\n%s", diff)
			}
		})
	}
}

func TestRequestParams_GenerateRequests(t *testing.T) {
	testTime := v2.Timestamp(time.Date(2022, 9, 15, 2, 40, 18, 0, time.UTC))

	cases := []struct {
		name      string
		reqParams RequestParams
		expected  []Request
		assertErr assert.ErrorAssertionFunc
	}{
		{
			name:      "empty",
			reqParams: RequestParams{},
			expected:  nil,
			assertErr: assert.Error, // because of missing values
		},
		{
			name: "single request, no ID, pending upstream fix",
			reqParams: RequestParams{
				PackageNames: []string{"foo"},
				Vulns:        []string{"CVE-2222-2222"},
				EventType:    v2.EventTypePendingUpstreamFix,
				Timestamp:    testTime.String(),
				Note:         "because because because because because",
			},
			expected: []Request{
				{
					Package: "foo",
					Aliases: []string{"CVE-2222-2222"},
					Event: v2.Event{
						Timestamp: testTime,
						Type:      v2.EventTypePendingUpstreamFix,
						Data: v2.PendingUpstreamFix{
							Note: "because because because because because",
						},
					},
				},
			},
		},
		{
			name: "single request, with ID, pending upstream fix",
			reqParams: RequestParams{
				PackageNames: []string{"foo"},
				Vulns:        []string{"CGA-2222-2222-2222"},
				EventType:    v2.EventTypePendingUpstreamFix,
				Timestamp:    testTime.String(),
				Note:         "because because because because because",
			},
			expected: []Request{
				{
					Package:    "foo",
					AdvisoryID: "CGA-2222-2222-2222",
					Event: v2.Event{
						Timestamp: testTime,
						Type:      v2.EventTypePendingUpstreamFix,
						Data: v2.PendingUpstreamFix{
							Note: "because because because because because",
						},
					},
				},
			},
		},
		{
			name: "multiple packages, multiple vulns, false positive",
			reqParams: RequestParams{
				PackageNames:      []string{"foo", "bar"},
				Vulns:             []string{"CVE-2222-2222", "CVE-3333-3333"},
				EventType:         v2.EventTypeFalsePositiveDetermination,
				Timestamp:         testTime.String(),
				FalsePositiveType: v2.FPTypeComponentVulnerabilityMismatch,
				Note:              "because because because because because",
			},
			expected: []Request{
				{
					Package: "foo",
					Aliases: []string{"CVE-2222-2222"},
					Event: v2.Event{
						Timestamp: testTime,
						Type:      v2.EventTypeFalsePositiveDetermination,
						Data: v2.FalsePositiveDetermination{
							Type: v2.FPTypeComponentVulnerabilityMismatch,
							Note: "because because because because because",
						},
					},
				},
				{
					Package: "foo",
					Aliases: []string{"CVE-3333-3333"},
					Event: v2.Event{
						Timestamp: testTime,
						Type:      v2.EventTypeFalsePositiveDetermination,
						Data: v2.FalsePositiveDetermination{
							Type: v2.FPTypeComponentVulnerabilityMismatch,
							Note: "because because because because because",
						},
					},
				},
				{
					Package: "bar",
					Aliases: []string{"CVE-2222-2222"},
					Event: v2.Event{
						Timestamp: testTime,
						Type:      v2.EventTypeFalsePositiveDetermination,
						Data: v2.FalsePositiveDetermination{
							Type: v2.FPTypeComponentVulnerabilityMismatch,
							Note: "because because because because because",
						},
					},
				},
				{
					Package: "bar",
					Aliases: []string{"CVE-3333-3333"},
					Event: v2.Event{
						Timestamp: testTime,
						Type:      v2.EventTypeFalsePositiveDetermination,
						Data: v2.FalsePositiveDetermination{
							Type: v2.FPTypeComponentVulnerabilityMismatch,
							Note: "because because because because because",
						},
					},
				},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			requests, err := tt.reqParams.GenerateRequests()
			if tt.assertErr != nil {
				tt.assertErr(t, err)
			}

			if diff := cmp.Diff(tt.expected, requests); diff != "" {
				t.Errorf("RequestParams.GenerateRequests() mismatch (-expected +actual):\n%s", diff)
			}
		})
	}
}
