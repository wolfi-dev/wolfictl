package v2

import (
	"fmt"
	"slices"
	"sort"

	"github.com/openvex/go-vex/pkg/vex"
	v1 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v1"
)

func MigrateV1Document(v1Doc *v1.Document) (*Document, error) {
	if v1Doc == nil {
		return nil, fmt.Errorf("v1Doc cannot be nil")
	}

	advisories, err := migrateV1Advisories(v1Doc.Advisories)
	if err != nil {
		return nil, fmt.Errorf("failed to migrate V1 advisories: %w", err)
	}

	doc := &Document{
		SchemaVersion: SchemaVersion,
		Package: Package{
			Name: v1Doc.Package.Name,
		},
		Advisories: advisories,
	}

	return doc, nil
}

func migrateV1Advisories(v1Advisories v1.Advisories) (Advisories, error) {
	if v1Advisories == nil {
		return nil, fmt.Errorf("v1Advisories cannot be nil")
	}

	advisories := make(Advisories, 0, len(v1Advisories))

	for id, entries := range v1Advisories {
		advisory, err := migrateV1Advisory(entries, id)
		if err != nil {
			return nil, fmt.Errorf("failed to migrate V1 advisory (ID: %s): %w", id, err)
		}

		advisories = append(advisories, *advisory)
	}

	// Ensure the advisory list is sorted before returning it.
	sort.Sort(advisories)

	return advisories, nil
}

func migrateV1Advisory(v1Advisory []v1.Entry, advisoryID string) (*Advisory, error) {
	events := make([]Event, 0, len(v1Advisory))
	for i, v1Entry := range v1Advisory {
		event, err := migrateV1Entry(v1Entry)
		if err != nil {
			return nil, fmt.Errorf("failed to migrate V1 entry (index: %d): %w", i, err)
		}

		events = append(events, *event)
	}

	return &Advisory{
		ID:     advisoryID,
		Events: events,
	}, nil
}

func migrateV1Entry(v1Entry v1.Entry) (*Event, error) {
	switch v1Entry.Status {
	case vex.StatusUnderInvestigation:
		return &Event{
			Type:      EventTypeDetection,
			Timestamp: Timestamp(v1Entry.Timestamp),
			Data: Detection{
				Type: DetectionTypeManual,
			},
		}, nil

	case vex.StatusAffected:
		var data interface{}
		action := v1Entry.ActionStatement
		if action != "" {
			data = TruePositiveDetermination{
				Note: action,
			}
		}
		return &Event{
			Type:      EventTypeTruePositiveDetermination,
			Timestamp: Timestamp(v1Entry.Timestamp),
			Data:      data,
		}, nil

	case vex.StatusFixed:
		return &Event{
			Type:      EventTypeFixed,
			Timestamp: Timestamp(v1Entry.Timestamp),
			Data: Fixed{
				FixedVersion: v1Entry.FixedVersion,
			},
		}, nil

	case vex.StatusNotAffected:
		fpType, err := migrateV1Justification(v1Entry.Justification)
		if err != nil {
			return nil, fmt.Errorf("failed to migrate V1 justification: %w", err)
		}

		return &Event{
			Type:      EventTypeFalsePositiveDetermination,
			Timestamp: Timestamp(v1Entry.Timestamp),
			Data: FalsePositiveDetermination{
				Type: fpType,
				Note: v1Entry.ImpactStatement,
			},
		}, nil
	}

	return nil, fmt.Errorf("unexpected VEX status: %s", v1Entry.Status)
}

func migrateV1Justification(j vex.Justification) (string, error) {
	switch j {
	case vex.ComponentNotPresent:
		return FPTypeComponentVulnerabilityMismatch, nil

	case vex.VulnerableCodeNotPresent:
		return "", fmt.Errorf("%s isn't allowed because it's ambiguous. Please use a v2 FPType as the justification instead to enable the migration to continue", j)

	case vex.VulnerableCodeNotInExecutePath:
		return FPTypeVulnerableCodeNotInExecutionPath, nil

	case vex.VulnerableCodeCannotBeControlledByAdversary:
		return FPTypeVulnerableCodeCannotBeControlledByAdversary, nil

	case vex.InlineMitigationsAlreadyExist:
		return FPTypeInlineMitigationsExist, nil
	}

	// To ease the migration to v2 via pre-migration review of existing data.
	if fpType := string(j); slices.Contains(FPTypes, fpType) {
		return fpType, nil
	}

	return "", fmt.Errorf("unrecognized VEX justification: %s", j)
}
