package sync

import (
	"fmt"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
	"golang.org/x/exp/slices"
)

const nakVersion = "0"

// A Need represents a requirement that must be met in order to consider a
// `secfixes` entry to be considered "in sync" with an `advisories` entry, or
// vice versa.
type Need interface {
	// Met returns a bool indicating whether this Need has already been satisfied.
	Met() bool

	// Resolve ensures that the Need has been met, by altering the underlying
	// configuration file if needed. Resolve is idempotent. If Resolve is unable to
	// apply the necessary resolution, it returns an error.
	//
	// If no error is returned, the caller can assume that subsequent calls to Met
	// will return true, assuming no further changes are made to the underlying
	// configuration.
	Resolve() error

	fmt.Stringer
}

type secfixesNeed struct {
	configEntry   configs.Entry[advisoryconfigs.Document]
	version, vuln string
}

func (n secfixesNeed) Met() bool {
	cfg := n.configEntry.Configuration()
	if cfg == nil {
		return false
	}

	if releaseVulnList, ok := cfg.Secfixes[n.version]; ok {
		return slices.Contains(releaseVulnList, n.vuln)
	}

	return false
}

func (n secfixesNeed) Resolve() error {
	if n.Met() {
		// nothing to do!
		return nil
	}

	updateSecfixes := advisoryconfigs.NewSecfixesSectionUpdater(func(cfg advisoryconfigs.Document) (advisoryconfigs.Secfixes, error) {
		secfixes := cfg.Secfixes

		secfixes[n.version] = append(secfixes[n.version], n.vuln)
		return secfixes, nil
	})

	err := n.configEntry.Update(updateSecfixes)
	if err != nil {
		return fmt.Errorf("unable to resolve need: %w", err)
	}

	return nil
}

func (n secfixesNeed) String() string {
	return fmt.Sprintf("%s: need a secfixes entry for %s: %s", n.configEntry.Configuration().Package.Name, n.version, n.vuln)
}

type advisoriesNeed struct {
	configEntry  configs.Entry[advisoryconfigs.Document]
	status       vex.Status
	vuln         string
	fixedVersion string
}

func (n advisoriesNeed) Met() bool {
	cfg := n.configEntry.Configuration()

	if cfg == nil {
		return false
	}

	entries, ok := cfg.Advisories[n.vuln]
	if !ok || len(entries) == 0 {
		return false
	}

	e := advisory.Latest(entries)
	return n.status == e.Status && n.fixedVersion == e.FixedVersion
}

func (n advisoriesNeed) Resolve() error {
	if n.Met() {
		// nothing to do!
		return nil
	}

	// We'll need to assume some values...
	timestamp := time.Now()
	justification := vex.Justification("")
	if n.status == vex.StatusNotAffected {
		justification = vex.VulnerableCodeNotInExecutePath
	}

	updateAdvisories := advisoryconfigs.NewAdvisoriesSectionUpdater(func(cfg advisoryconfigs.Document) (advisoryconfigs.Advisories, error) {
		newAdvisoryEntry := advisoryconfigs.Entry{
			Timestamp:     timestamp,
			Status:        n.status,
			Justification: justification,
			FixedVersion:  n.fixedVersion,
		}

		advisories := cfg.Advisories

		advisories[n.vuln] = append(advisories[n.vuln], newAdvisoryEntry)
		return advisories, nil
	})

	err := n.configEntry.Update(updateAdvisories)
	if err != nil {
		return fmt.Errorf("unable to resolve need: %w", err)
	}

	return nil
}

func (n advisoriesNeed) String() string {
	inFixedVersion := ""
	if ver := n.fixedVersion; ver != "" {
		inFixedVersion = fmt.Sprintf(" in %s", ver)
	}

	cfg := n.configEntry.Configuration()
	return fmt.Sprintf("%s: need an advisories entry for %s: %s%s", cfg.Package.Name, n.vuln, n.status, inFixedVersion)
}

func DetermineNeeds(selection configs.Selection[advisoryconfigs.Document]) ([]Need, error) {
	var needs []Need

	selection.Each(func(entry configs.Entry[advisoryconfigs.Document]) {
		secfixesNeeds := getSecfixesNeeds(entry)
		needs = append(needs, secfixesNeeds...)

		advisoriesNeeds := getAdvisoriesNeeds(entry)
		needs = append(needs, advisoriesNeeds...)
	})

	return needs, nil
}

// getSecfixesNeeds returns a list of the DetermineNeeds that must be met in the `secfixes`
// section, as informed by analyzing the `advisories` section.
func getSecfixesNeeds(entry configs.Entry[advisoryconfigs.Document]) []Need {
	cfg := entry.Configuration()

	var needs []Need
	for vuln, entries := range cfg.Advisories {
		if len(entries) == 0 {
			continue
		}

		advisoryEntry := advisory.Latest(entries)

		switch advisoryEntry.Status {
		case vex.StatusFixed:
			needs = append(needs, secfixesNeed{
				configEntry: entry,
				version:     advisoryEntry.FixedVersion,
				vuln:        vuln,
			})

		case vex.StatusNotAffected:
			needs = append(needs, secfixesNeed{
				configEntry: entry,
				version:     nakVersion,
				vuln:        vuln,
			})
		}
	}

	return needs
}

// getAdvisoriesNeeds returns a list of the DetermineNeeds that must be met in the `advisories`
// section, as informed by analyzing the `secfixes` section.
func getAdvisoriesNeeds(
	entry configs.Entry[advisoryconfigs.Document],
) []Need {
	cfg := entry.Configuration()

	var needs []Need
	for version, vulns := range cfg.Secfixes {
		for _, vuln := range vulns {
			neededStatus := vex.StatusFixed
			if version == nakVersion {
				neededStatus = vex.StatusNotAffected
			}

			neededFixedVersion := version
			if neededStatus == vex.StatusNotAffected {
				neededFixedVersion = ""
			}

			needs = append(needs, advisoriesNeed{
				configEntry:  entry,
				status:       neededStatus,
				vuln:         vuln,
				fixedVersion: neededFixedVersion,
			})
		}
	}

	return needs
}

// Unmet filters the given set of DetermineNeeds down to just the set of needs that are
// not met.
func Unmet(needs []Need) []Need {
	var result []Need

	for _, need := range needs {
		if !need.Met() {
			result = append(result, need)
		}
	}

	return result
}
