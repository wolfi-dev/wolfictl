package question

import (
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/question"
)

var (
	IsFalsePositive = question.Question[advisory.Request]{
		Text: "Any obvious sign that this is a false positive?",
		Choices: []question.Choice[advisory.Request]{
			{
				Text: "No",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					return req, &IsPackageSupported
				},
			},
			{
				Text: "Yes",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					e := v2.Event{
						Timestamp: v2.Now(),
						Type:      v2.EventTypeFalsePositiveDetermination,
					}

					req.Event = e
					return req, &WhyFalsePositive
				},
			},
		},
	}

	WhyFalsePositive = question.Question[advisory.Request]{
		Text: "Why is this a false positive?",
		Choices: []question.Choice[advisory.Request]{
			{
				Text: "The maintainers don't agree that this is a security problem.",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeVulnerabilityRecordAnalysisContested,
						Note: "The maintainers don't agree that this is a security problem.",
					}
					// TODO: Get more specific: Link to a citation? Where is the dispute recorded and who made it?
					return req, nil
				},
			},
			{
				Text: "This is specific to another distro, not ours.",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeComponentVulnerabilityMismatch,
						Note: "This is specific to another distro, not ours.",
					}
					// TODO: Which distro?
					return req, nil
				},
			},
			{
				Text: "This seems to refer to a past version of the software, not the version we have now.",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeVulnerableCodeVersionNotUsed,
						Note: "This seems to refer to a past version of the software, not the version we have now.",
					}
					// TODO: Which version? Why doesn't this apply to our current version?
					return req, nil
				},
			},
		},
	}

	IsPackageSupported = question.Question[advisory.Request]{
		Text: "Is this package still supported upstream?",
		Choices: []question.Choice[advisory.Request]{
			{
				Text: "Yes",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					return req, nil
				},
			},
			{
				Text: "No",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					// TODO: Why not? What's the upstream status and how do we know?
					return req, nil
				},
			},
		},
	}
)
