package question

import (
	"fmt"

	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
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
				Choose: func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					e := v2.Event{
						Timestamp: v2.Now(),
						Type:      v2.EventTypeFalsePositiveDetermination,
					}

					req.Event = e
					return req, &WhyFalsePositive, nil
				},
			},
			{
				Text:   "I'm not sure",
				Choose: question.NewChooseFunc(&IsFalsePositiveAskForHelp),
			},
		},
	}

	IsFalsePositiveAskForHelp = question.NewTerminatingMessage[advisory.Request](
		fmt.Sprintf("No problem! Please ask for help %s! You can say something like 'I could use help determining if this is a false positive...'", destinationForHelp),
	)

	WhyFalsePositive = question.Question[advisory.Request]{
		Text: "Why is this a false positive?",
		Answer: question.MultipleChoice[advisory.Request]{
			{
				Text: "The maintainers don't agree that this is a security problem.",
				Choose: func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeVulnerabilityRecordAnalysisContested,
					}
					return req, &ReferenceForMaintainersDisagree, nil
				},
			},
			{
				Text: "This is specific to another distro, not ours.",
				Choose: func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeComponentVulnerabilityMismatch,
					}
					return req, &WhichOtherDistro, nil
				},
			},
			{
				Text: "This seems to refer to a past version of the software, not the version we have now.",
				Choose: func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeVulnerableCodeVersionNotUsed,
					}
					return req, &ProvidePastVersionReferencedByVulnerability, nil
				},
			},
			{
				// TODO: Make this show only for Go vulnerability matches?
				// TODO: Automate this scan?
				Text: "Govulncheck shows that the affected code is not present in our build.",
				Choose: func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeVulnerableCodeNotIncludedInPackage,
						Note: "Govulncheck shows that the affected code is not present in our build.",
					}
					return req, nil, nil
				},
			},
		},
	}

	ProvidePastVersionReferencedByVulnerability = question.Question[advisory.Request]{
		Text: "Please provide the past version of the software referenced by the vulnerability to show that this doesn't affect our version.",
		Answer: question.AcceptText[advisory.Request](func(req advisory.Request, text string) (advisory.Request, *question.Question[advisory.Request], error) {
			req.Event.Data = v2.FalsePositiveDetermination{
				Type: v2.FPTypeVulnerableCodeVersionNotUsed,
				Note: fmt.Sprintf("This seems to refer to a past version of the software, not the version we have now. Past version: %s", text),
			}

			return req, nil, nil
		}),
	}

	ReferenceForMaintainersDisagree = question.Question[advisory.Request]{
		Text: "Please provide a web URL to a source that shows the maintainers don't agree that this is a security problem.",
		Answer: question.AcceptText[advisory.Request](func(req advisory.Request, text string) (advisory.Request, *question.Question[advisory.Request], error) {
			req.Event.Data = v2.FalsePositiveDetermination{
				Type: v2.FPTypeVulnerabilityRecordAnalysisContested,
				Note: fmt.Sprintf("The maintainers don't agree that this is a security problem. Source: %s", text),
			}

			return req, nil, nil
		}),
	}

	WhichOtherDistro = question.Question[advisory.Request]{
		Text: "Which other distro is this specific to?",
		Answer: question.MultipleChoice[advisory.Request]{
			{
				Text: "Alpine", Choose: question.ChooseFunc[advisory.Request](func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeComponentVulnerabilityMismatch,
						Note: "This vulnerability is specific to Alpine.",
					}
					return req, nil, nil
				}),
			},
			{
				Text: "Amazon", Choose: question.ChooseFunc[advisory.Request](func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeComponentVulnerabilityMismatch,
						Note: "This vulnerability is specific to Amazon.",
					}
					return req, nil, nil
				}),
			},
			{
				Text: "Debian", Choose: question.ChooseFunc[advisory.Request](func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeComponentVulnerabilityMismatch,
						Note: "This vulnerability is specific to Debian.",
					}
					return req, nil, nil
				}),
			},
			{
				Text: "Fedora", Choose: question.ChooseFunc[advisory.Request](func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeComponentVulnerabilityMismatch,
						Note: "This vulnerability is specific to Fedora.",
					}
					return req, nil, nil
				}),
			},
			{
				Text: "RHEL", Choose: question.ChooseFunc[advisory.Request](func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeComponentVulnerabilityMismatch,
						Note: "This vulnerability is specific to RHEL.",
					}
					return req, nil, nil
				}),
			},
			{
				Text: "SUSE/SLES", Choose: question.ChooseFunc[advisory.Request](func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeComponentVulnerabilityMismatch,
						Note: "This vulnerability is specific to SUSE/SLES.",
					}
					return req, nil, nil
				}),
			},
			{
				Text: "Ubuntu", Choose: question.ChooseFunc[advisory.Request](func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					req.Event.Data = v2.FalsePositiveDetermination{
						Type: v2.FPTypeComponentVulnerabilityMismatch,
						Note: "This vulnerability is specific to Ubuntu.",
					}
					return req, nil, nil
				}),
			},
		},
	}

	IsPackageSupported = question.Question[advisory.Request]{
		Text: "Is this package still supported upstream?", // TODO: automate this lookup!
		Answer: question.MultipleChoice[advisory.Request]{
			{
				Text: "Yes",
				Choose: func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					return req, &HasFixBeenAttempted, nil
				},
			},
			{
				Text: "No",
				Choose: func(req advisory.Request) (advisory.Request, *question.Question[advisory.Request], error) {
					return req, &ReferenceForNotSupportedUpstream, nil
				},
			},
			{
				Text:   "I'm not sure",
				Choose: question.NewChooseFunc[advisory.Request](&IsPackageSupportedAskForHelp),
			},
		},
	}

	IsPackageSupportedAskForHelp = question.NewTerminatingMessage[advisory.Request](
		fmt.Sprintf("No problem! Please ask for help %s! You can say something like 'I could use help determining if this package is still supported upstream...'", destinationForHelp),
	)

	ReferenceForNotSupportedUpstream = question.Question[advisory.Request]{
		Text: "Please provide a web URL to a source that shows the package is no longer supported upstream.",
		Answer: question.AcceptText[advisory.Request](func(req advisory.Request, text string) (advisory.Request, *question.Question[advisory.Request], error) {
			req.Event.Type = v2.EventTypeFixNotPlanned
			req.Event.Data = v2.FixNotPlanned{
				Note: fmt.Sprintf("Package is no longer supported upstream. Source: %s", text),
			}

			return req, nil, nil
		}),
	}

	HasFixBeenAttempted = question.Question[advisory.Request]{
		Text: "Have you tried to fix the vulnerability yet?",
		Answer: question.MultipleChoice[advisory.Request]{
			{
				Text: "Yes, but I need help.", Choose: question.NewChooseFunc[advisory.Request](&HasFixBeenAttemptedAskForHelp),
			},
			{
				Text: "Yes, and I'm surprised this is still showing up in a scan.", Choose: question.NewChooseFunc[advisory.Request](&HasFixBeenAttemptedAskForHelp),
			},
			{
				Text: "No, I need help.", Choose: question.NewChooseFunc[advisory.Request](&HasFixBeenAttemptedAskForHelp),
			},
			{
				Text: "No, I'll try to fix this and then come back to the advisory data entry later.", Choose: question.NewChooseFunc[advisory.Request](&MovingOnForNow),
			},
		},
	}

	HasFixBeenAttemptedAskForHelp = question.NewTerminatingMessage[advisory.Request](
		fmt.Sprintf("No problem! Please ask for help %s! You can say something like 'I could use help fixing this vulnerability...'", destinationForHelp),
	)

	MovingOnForNow = question.NewTerminatingMessage[advisory.Request](
		"Sounds good! Let's move on for now. If you need help later, just ask!",
	)
)

const (
	destinationForHelp = "in the #cve Slack channel"
)
