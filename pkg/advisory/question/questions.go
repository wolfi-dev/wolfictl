package question

import (
	"fmt"

	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/question"
)

var (
	IsFalsePositive = question.Question[advisory.Request]{
		Text: "Is this a false positive?",
		Answer: question.MultipleChoice[advisory.Request]{
			{
				Text:   "No",
				Choose: question.NewChooseFunc(&IsPackageSupported),
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
			{
				Text:   "I'm not sure",
				Choose: TODOFinal, // TODO: wiki link for "how to spot a false positive"?
			},
		},
	}

	WhyFalsePositive = question.Question[advisory.Request]{
		Text: "Why is this a false positive?",
		Answer: question.MultipleChoice[advisory.Request]{
			{
				Text: "The maintainers don't agree that this is a security problem.",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeVulnerabilityRecordAnalysisContested,
					}
					return req, &ReferenceForMaintainersDisagree
				},
			},
			{
				Text: "This is specific to another distro, not ours.",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeComponentVulnerabilityMismatch,
						Note: "This is specific to another distro, not ours.",
					}
					return req, &WhichOtherDistro
				},
			},
			{
				Text: "This seems to refer to a past version of the software, not the version we have now.",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeVulnerableCodeVersionNotUsed,
						Note: "This seems to refer to a past version of the software, not the version we have now.",
					}
					return req, &ProvidePastVersionReferencedByVulnerability
				},
			},
			{
				// TODO: Make this show only for Go vulnerability matches?
				// TODO: Automate this scan?
				Text: "Govulncheck shows that the affected code is not present in our build.",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeVulnerableCodeNotIncludedInPackage,
						Note: "Govulncheck shows that the affected code is not present in our build.",
					}
					return req, nil
				},
			},
		},
	}

	ProvidePastVersionReferencedByVulnerability = question.Question[advisory.Request]{
		Text: "Please provide the past version of the software referenced by the vulnerability to show that this doesn't affect our version.",
		Answer: question.AcceptText[advisory.Request](func(req advisory.Request, text string) (updated advisory.Request, next *question.Question[advisory.Request]) {
			req.Event.Data = v2.FalsePositiveDetermination{
				Type: v2.FPTypeVulnerableCodeVersionNotUsed,
				Note: fmt.Sprintf("This seems to refer to a past version of the software, not the version we have now. Past version: %s", text),
			}

			return req, nil
		}),
	}

	ReferenceForMaintainersDisagree = question.Question[advisory.Request]{
		Text: "Please provide a web URL to a source that shows the maintainers don't agree that this is a security problem.",
		Answer: question.AcceptText[advisory.Request](func(req advisory.Request, text string) (updated advisory.Request, next *question.Question[advisory.Request]) {
			req.Event.Data = v2.FalsePositiveDetermination{
				Type: v2.FPTypeVulnerabilityRecordAnalysisContested,
				Note: fmt.Sprintf("The maintainers don't agree that this is a security problem. Source: %s", text),
			}

			return req, nil
		}),
	}

	WhichOtherDistro = question.Question[advisory.Request]{
		Text: "Which other distro is this specific to?",
		Answer: question.MultipleChoice[advisory.Request]{
			{
				Text: "Alpine", Choose: TODOFinal,
			},
			{
				Text: "Amazon", Choose: TODOFinal,
			},
			{
				Text: "Debian", Choose: TODOFinal,
			},
			{
				Text: "Fedora", Choose: TODOFinal,
			},
			{
				Text: "RHEL", Choose: TODOFinal,
			},
			{
				Text: "SUSE/SLES", Choose: TODOFinal,
			},
			{
				Text: "Ubuntu", Choose: TODOFinal,
			},
		},
	}

	IsPackageSupported = question.Question[advisory.Request]{
		Text: "Is this package still supported upstream?", // TODO: automate this lookup!
		Answer: question.MultipleChoice[advisory.Request]{
			{
				Text: "Yes",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					return req, &HasFixBeenAttempted
				},
			},
			{
				Text: "No",
				Choose: func(req advisory.Request) (updated advisory.Request, next *question.Question[advisory.Request]) {
					return req, &ReferenceForNotSupportedUpstream
				},
			},
			{
				Text:   "I'm not sure",
				Choose: TODOFinal, // TODO: wiki link for "how to check if a package is still supported"?
			},
		},
	}

	ReferenceForNotSupportedUpstream = question.Question[advisory.Request]{
		Text: "Please provide a web URL to a source that shows the package is no longer supported upstream.",
		Answer: question.AcceptText[advisory.Request](func(req advisory.Request, text string) (updated advisory.Request, next *question.Question[advisory.Request]) {
			req.Event.Type = v2.EventTypeFixNotPlanned
			req.Event.Data = v2.FixNotPlanned{
				Note: fmt.Sprintf("Package is no longer supported upstream. Source: %s", text),
			}

			return req, nil
		}),
	}

	HasFixBeenAttempted = question.Question[advisory.Request]{
		Text: "Have you tried to fix the vulnerability yet?",
		Answer: question.MultipleChoice[advisory.Request]{
			{
				Text: "Yes, but I need help.", Choose: TODOFinal,
			},
			{
				Text: "Yes, and I'm surprised this is still showing up in a scan.", Choose: TODOFinal, // TODO: wiki link for "the vuln I fixed is still showing up"?
			},
			{
				Text: "No, I need help.", Choose: TODOFinal, // TODO: CTA: Ask for help in #cve or something
			},
			{
				Text: "No, I'll try to fix this and then come back to the advisory data entry later.", Choose: TODOFinal,
			},
		},
	}
)

var (
	// TODO is a placeholder answer for the advisory interview flow.
	TODO = question.NewChooseFunc[advisory.Request](&question.Question[advisory.Request]{
		Text: "TODO",
	})

	// TODOFinal is a placeholder for a terminating answer in the advisory interview flow.
	TODOFinal = question.NewChooseFunc[advisory.Request](nil)
)
