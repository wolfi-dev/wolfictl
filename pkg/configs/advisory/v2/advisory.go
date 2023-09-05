package v2

import (
	"errors"
	"fmt"
	"sort"

	"github.com/samber/lo"
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
func (adv Advisory) ResolvedAtVersion(version string) bool {
	if len(adv.Events) == 0 {
		return false
	}

	switch latest := adv.Latest(); latest.Type {
	case EventTypeFalsePositiveDetermination, EventTypeFixNotPlanned, EventTypeAnalysisNotPlanned:
		return true

	case EventTypeFixed:
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

		return givenVersion.GreaterThanOrEqual(fixedVersion)

	default:
		return false
	}
}

// Validate returns an error if the advisory is invalid.
func (adv Advisory) Validate() error {
	return labelError(adv.ID,
		errors.Join(
			vuln.ValidateID(adv.ID),
			adv.validateAliases(),
			adv.validateEvents(),
		),
	)
}

func (adv Advisory) validateAliases() error {
	return labelError("aliases",
		errors.Join(lo.Map(adv.Aliases, func(alias string, _ int) error {
			return vuln.ValidateID(alias)
		})...),
	)
}

func (adv Advisory) validateEvents() error {
	if len(adv.Events) == 0 {
		return fmt.Errorf("there must be at least one event")
	}

	return labelError("events",
		errors.Join(lo.Map(adv.Events, func(event Event, i int) error {
			err := event.Validate()
			if err != nil {
				return labelError(fmt.Sprintf("event %d", i), err)
			}
			return nil
		})...),
	)
}
