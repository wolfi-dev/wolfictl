package advisory

import (
	"context"
	"errors"
	"fmt"
	"slices"

	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/chainguard-dev/clog"
	adv2 "github.com/wolfi-dev/wolfictl/pkg/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
)

// ErrNoSourceAdvisoriesSelected is returned when provided package name and
// vulnerability ID filters match no advisories in the source index.
var ErrNoSourceAdvisoriesSelected = errors.New("no source advisories selected")

type RebaseOptions struct {
	SourceIndex      *configs.Index[v2.Document]
	DestinationIndex *configs.Index[v2.Document]

	// PackageName is the name of the package to rebase.
	PackageName string

	// Optionally filter to a single advisory by vulnerability ID (alias) or
	// advisory ID, and only the matching advisory in the specificed source advisory
	// document will be copied over.
	VulnerabilityID string

	// Used for any new events added to the destination.
	CurrentTime v2.Timestamp
}

// Rebase updates the destination package's advisories (or a specific advisory)
// with the latest events from the source advisories. The source and destination
// packages are assumed to be in two separate indexes, meaning they are assumed
// to be in separate repositories.
func Rebase(ctx context.Context, opts RebaseOptions) error {
	log := clog.FromContext(ctx).With("package", opts.PackageName, "vulnerability", opts.VulnerabilityID, "newEventTimestamp", opts.CurrentTime)

	if opts.CurrentTime.IsZero() {
		return errors.New("current time must be set")
	}

	// Get source advisories

	srcEntry, err := opts.SourceIndex.Select().WhereName(opts.PackageName).First()
	if err != nil {
		if errors.Is(err, configs.ErrNoEntries) {
			log.Warn("no source advisories found for package, skipping")
			return nil
		}
		return fmt.Errorf("finding source document for %q: %w", opts.PackageName, err)
	}
	srcDoc := srcEntry.Configuration()

	var srcAdvs []v2.Advisory
	for _, adv := range srcDoc.Advisories {
		// Only include advisories that match the user's filter, if one was specified.
		if opts.VulnerabilityID == "" || adv.DescribesVulnerability(opts.VulnerabilityID) {
			srcAdvs = append(srcAdvs, adv)
		}
	}

	if len(srcAdvs) == 0 {
		if opts.VulnerabilityID != "" {
			return fmt.Errorf("no source data found for vulnerability with ID %q in package %q", opts.VulnerabilityID, opts.PackageName)
		}

		return ErrNoSourceAdvisoriesSelected
	}

	log.Info("identified source advisories matching user's criteria", "count", len(srcAdvs))

	// Update destination advisories with source advisories

	for _, srcAdv := range srcAdvs {
		srcLatestEvent := srcAdv.Latest()
		log := log.With("srcAdvID", srcAdv.ID, "srcAdvLatestEventType", srcLatestEvent.Type)

		// Only update advisories where the latest event of the source advisory is not:
		//
		// — "detection" (we'll rely on the automated APK scanning for the new
		// repository to provide up-to-date data for detection events), or
		//
		// — "fixed" (values for "fixed version" would be incorrect since they describe
		// a separate APK repository; additionally, we don't consider a package's first
		// version to "fix" any vulnerabilities, since those vulnerabilities were never
		// present in the current package's lineage).
		if slices.Contains(
			[]string{v2.EventTypeDetection, v2.EventTypeFixed},
			srcLatestEvent.Type,
		) {
			log.Infof("skipping advisory with latest event of type %s", srcLatestEvent.Type)
			continue
		}

		// Use the current time for the copied event's timestamp.
		srcLatestEvent.Timestamp = opts.CurrentTime

		// There may or may not be an existing destination advisory to update. It's not
		// expected to have the same CGA ID, but it will have the same aliases.
		aliases := srcAdv.Aliases

		if err := opts.updateDestinationIndexWithNewAdvisoryData(clog.WithLogger(ctx, log), aliases, srcLatestEvent); err != nil {
			return fmt.Errorf("updating destination with new advisory data for %q: %w", srcAdv.ID, err)
		}
	}

	return nil
}

func (opts RebaseOptions) updateDestinationIndexWithNewAdvisoryData(ctx context.Context, aliases []string, event v2.Event) error {
	log := clog.FromContext(ctx)
	log.Debug("updating destination with new advisory data")

	dstDoc, err := opts.getDestinationDocument(ctx)
	if err != nil {
		return fmt.Errorf("preparing destination to receive advisory data for %q: %w", opts.PackageName, err)
	}

	log.Debug("looking for existing destination advisory to update", "srcAdvAliases", aliases)
	var dstAdv v2.Advisory
	var exists bool
	if dstAdv, exists = dstDoc.Advisories.GetByAnyVulnerability(aliases...); exists {
		log := log.With("dstAdvID", dstAdv.ID, "dstAdvLatestEventType", dstAdv.Latest().Type)
		log.Debug("found existing destination advisory to update")

		if dstAdv.Resolved() {
			log.Warn("destination advisory was already resolved, but proceeding to add new event from source per user's request")
		}
		dstAdv.Events = append(dstAdv.Events, event)
	} else {
		log.Debug("no existing destination advisory found, creating new one")

		dstAdvID, err := GenerateCGAID()
		if err != nil {
			return fmt.Errorf("generating new CGA ID: %w", err)
		}

		log := log.With("dstAdvID", dstAdvID)
		log.Debug("creating new advisory for destination")

		newAdv := v2.Advisory{
			ID:      dstAdvID,
			Aliases: aliases,
			Events:  []v2.Event{event},
		}
		dstAdv = newAdv
	}

	log.Debug("updating destination with new advisory data")

	return opts.DestinationIndex.Select().WhereName(opts.PackageName).Update(ctx, adv2.NewAdvisoriesSectionUpdater(func(doc v2.Document) (v2.Advisories, error) {
		advisories := doc.Advisories
		advisories = advisories.Upsert(dstAdv.ID, dstAdv)
		return advisories, nil
	}))
}

func (opts RebaseOptions) getDestinationDocument(ctx context.Context) (*v2.Document, error) {
	log := clog.FromContext(ctx)

	// An advisories document for the destination path may or may not exist already.
	dstDoc, err := opts.DestinationIndex.Select().WhereName(opts.PackageName).First()
	if err == nil {
		return dstDoc.Configuration(), nil
	}

	if !errors.Is(err, configs.ErrNoEntries) {
		return nil, fmt.Errorf("finding destination document for %q: %w", opts.PackageName, err)
	}

	newAdvFileName := fmt.Sprintf("%s.advisories.yaml", opts.PackageName)
	log.Debug("creating new advisories document for destination package", "newAdvFileName", newAdvFileName)

	if err := opts.DestinationIndex.Create(ctx, newAdvFileName, (v2.Document{
		SchemaVersion: v2.SchemaVersion,
		Package: v2.Package{
			Name: opts.PackageName,
		},
		Advisories: make([]v2.Advisory, 0),
	})); err != nil {
		return nil, fmt.Errorf("creating new advisories document for %q: %w", opts.PackageName, err)
	}

	dstDoc, err = opts.DestinationIndex.Select().WhereName(opts.PackageName).First()
	if err != nil {
		return nil, fmt.Errorf("finding just-now created destination document for %q: %w", opts.PackageName, err)
	}

	return dstDoc.Configuration(), nil
}
