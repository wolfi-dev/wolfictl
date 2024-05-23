package v2

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/internal/errorhelpers"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
)

type Advisory struct {
	ID string `yaml:"id"`

	// Aliases lists any known IDs of this vulnerability in databases.
	Aliases []string `yaml:"aliases,omitempty"`

	// Events is a list of timestamped events that occurred during the investigation
	// and resolution of the vulnerability.
	Events []Event `yaml:"events"`
}

// IsZero returns true if the advisory has no data.
func (adv Advisory) IsZero() bool {
	return adv.ID == "" && len(adv.Aliases) == 0 && len(adv.Events) == 0
}

// DescribesVulnerability returns true if the advisory cites the given
// vulnerability ID in either its ID or its aliases.
func (adv Advisory) DescribesVulnerability(vulnID string) bool {
	return adv.ID == vulnID || slices.Contains(adv.Aliases, vulnID)
}

// Latest returns the latest event in the advisory.
func (adv Advisory) Latest() Event {
	if len(adv.Events) == 0 {
		return Event{}
	}

	sorted := adv.SortedEvents()
	return sorted[len(adv.Events)-1]
}

// SortedEvents returns the events in the advisory, sorted by timestamp, from
// oldest to newest.
func (adv Advisory) SortedEvents() []Event {
	// avoid mutating the original slice
	sorted := make([]Event, len(adv.Events))
	copy(sorted, adv.Events)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	return sorted
}

// Resolved returns true if the advisory indicates that the vulnerability does
// not presently affect the distro package and/or that no further investigation
// is planned.
func (adv Advisory) Resolved() bool {
	if len(adv.Events) == 0 {
		return false
	}

	switch adv.Latest().Type {
	case EventTypeDetection, EventTypeTruePositiveDetermination:
		return false

	default:
		return true
	}
}

// ResolvedAtVersion returns true if the advisory indicates that the
// vulnerability does not affect the distro package at the given package
// version, or that no further investigation is planned.
func (adv Advisory) ResolvedAtVersion(version, packageType string) bool {
	if len(adv.Events) == 0 {
		return false
	}

	switch latest := adv.Latest(); latest.Type {
	case EventTypeFalsePositiveDetermination,
		EventTypeFixNotPlanned,
		EventTypeAnalysisNotPlanned,
		EventTypePendingUpstreamFix:
		return true

	case EventTypeFixed:
		return adv.isFixedVersion(version, packageType, latest)

	default:
		return false
	}
}

// ConcludedAtVersion returns true if the advisory indicates that the
// vulnerability has been solved, or those where no change is
// expected to fix the CVE in the upstream code.
func (adv Advisory) ConcludedAtVersion(version, packageType string) bool {
	if len(adv.Events) == 0 {
		return false
	}

	latest := adv.Latest()
	if latest.Type == EventTypePendingUpstreamFix {
		return false
	}
	// NOTE: The resolved set is part of the concluded one
	// with the exception of the pending-upstream-fix event type.
	return adv.ResolvedAtVersion(version, packageType)
}

// isFixedVersion determines whether the vulnerability discovered for the provided
// version has been fixed.
func (adv Advisory) isFixedVersion(version, packageType string, latest Event) bool {
	if packageType != "apk" {
		return false
	}

	givenVersion, err := versions.NewVersion(version)
	if err != nil {
		return false
	}
	fixedData, ok := latest.Data.(Fixed)
	if !ok {
		return false
	}
	fixedVersion, err := versions.NewVersion(fixedData.FixedVersion)
	if err != nil {
		return false
	}

	fixedInLatest := givenVersion.GreaterThanOrEqual(fixedVersion)
	return fixedInLatest
}

// Validate returns an error if the advisory is invalid.
func (adv Advisory) Validate() error {
	return errorhelpers.LabelError(adv.ID,
		errors.Join(
			vuln.ValidateID(adv.ID),
			adv.validateAliases(),
			adv.validateEvents(),
		),
	)
}

func (adv Advisory) validateAliases() error {
	var errs []error

	// Validate aliases as a collection
	errs = append(errs, validateNoDuplicates(adv.Aliases))

	// Loop through aliases to validate each one
	for _, alias := range adv.Aliases {
		errs = append(errs,
			validateAliasFormat(alias),
			validateAliasIsNotAdvisoryID(alias, adv.ID),
		)
	}

	return errorhelpers.LabelError("aliases", errors.Join(errs...))
}

func (adv Advisory) validateEvents() error {
	if len(adv.Events) == 0 {
		return fmt.Errorf("there must be at least one event")
	}

	return errorhelpers.LabelError("events",
		errors.Join(lo.Map(adv.Events, func(event Event, i int) error {
			err := event.Validate()
			if err != nil {
				// show the event index as 1-based, not 0-based, just for ease of understanding
				return errorhelpers.LabelError(fmt.Sprintf("event %d", i+1), err)
			}
			return nil
		})...),
	)
}

func validateAliasFormat(alias string) error {
	switch {
	case vuln.RegexCVE.MatchString(alias),
		vuln.RegexGHSA.MatchString(alias),
		vuln.RegexGO.MatchString(alias):
		return nil
	default:
		return fmt.Errorf("%q is not a valid CVE ID, GHSA ID or Go vuln ID", alias)
	}
}

func validateAliasIsNotAdvisoryID(alias, advisoryID string) error {
	if advisoryID == alias {
		return fmt.Errorf("alias %q cannot duplicate the advisory's ID", alias)
	}

	return nil
}

func validateNoDuplicates(items []string) error {
	seen := make(map[string]struct{})
	for _, item := range items {
		if _, ok := seen[item]; ok {
			return fmt.Errorf("%q is duplicated in the list", item)
		}
		seen[item] = struct{}{}
	}
	return nil
}
