package sync

import (
	"fmt"
	"time"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/vex/pkg/vex"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
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
	index         *configs.Index
	configEntry   configs.Entry
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
		return nil
	}

	updater := advisory.NewConfigUpdaterForSecfixes(n.index, func(secfixes build.Secfixes) (build.Secfixes, error) {
		secfixes[n.version] = append(secfixes[n.version], n.vuln)
		return secfixes, nil
	})

	err := n.index.Update(n.configEntry, updater)
	if err != nil {
		return fmt.Errorf("unable to resolve need: %w", err)
	}

	return nil
}

func (n secfixesNeed) String() string {
	return fmt.Sprintf("%s: need a secfixes entry for %s: %s", n.configEntry.Configuration().Package.Name, n.version, n.vuln)
}

type advisoriesNeed struct {
	index        *configs.Index
	configEntry  configs.Entry
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
		return nil
	}

	// We'll need to assume some values...
	timestamp := time.Now()
	justification := vex.Justification("")
	if n.status == vex.StatusNotAffected {
		justification = vex.VulnerableCodeNotInExecutePath
	}

	updater := advisory.NewConfigUpdaterForAdvisories(n.index, func(advisories build.Advisories) (build.Advisories, error) {
		newAdvisoryEntry := build.AdvisoryContent{
			Timestamp:     timestamp,
			Status:        n.status,
			Justification: justification,
			FixedVersion:  n.fixedVersion,
		}
		advisories[n.vuln] = append(advisories[n.vuln], newAdvisoryEntry)
		return advisories, nil
	})

	err := n.index.Update(n.configEntry, updater)
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

func NeedsFromIndex(index *configs.Index) ([]Need, error) {
	var needs []Need

	calculateNeedsForConfig := func(e configs.Entry) error {
		secfixesNeeds := GetSecfixesNeeds(e, index)
		needs = append(needs, secfixesNeeds...)

		advisoriesNeeds := GetAdvisoriesNeeds(e, index)
		needs = append(needs, advisoriesNeeds...)

		return nil
	}

	err := index.ForEach(calculateNeedsForConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to calculate needs for index: %w", err)
	}

	return needs, nil
}

// GetSecfixesNeeds returns a list of the Needs that must be met in the `secfixes`
// section, as informed by analyzing the `advisories` section.
func GetSecfixesNeeds(configEntry configs.Entry, index *configs.Index) []Need {
	var needs []Need

	cfg := configEntry.Configuration()
	for vuln, entries := range cfg.Advisories {
		if len(entries) == 0 {
			continue
		}

		entry := advisory.Latest(entries)

		switch entry.Status {
		case vex.StatusFixed:
			needs = append(needs, secfixesNeed{
				index:       index,
				configEntry: configEntry,
				version:     entry.FixedVersion,
				vuln:        vuln,
			})

		case vex.StatusNotAffected:
			needs = append(needs, secfixesNeed{
				index:       index,
				configEntry: configEntry,
				version:     nakVersion,
				vuln:        vuln,
			})
		}
	}

	return needs
}

// GetAdvisoriesNeeds returns a list of the Needs that must be met in the `advisories`
// section, as informed by analyzing the `secfixes` section.
func GetAdvisoriesNeeds(configEntry configs.Entry, index *configs.Index) []Need {
	var needs []Need

	cfg := configEntry.Configuration()
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
				index:        index,
				configEntry:  configEntry,
				status:       neededStatus,
				vuln:         vuln,
				fixedVersion: neededFixedVersion,
			})
		}
	}

	return needs
}
