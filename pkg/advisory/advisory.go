package advisory

import (
	"fmt"
	"sort"

	"chainguard.dev/melange/pkg/build"
	"github.com/dprotaso/go-yit"
	"github.com/pkg/errors"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"gopkg.in/yaml.v3"
)

type CreateOptions struct {
	// The Index of package configs on which to operate.
	Index *configs.Index

	// Pathname is the filepath for the configuration to which Create will add the
	// new advisory.
	Pathname string

	// Vuln is the vulnerability ID used to name the new advisory.
	Vuln string

	// InitialAdvisoryEntry is the entry that will be added to the new advisory.
	InitialAdvisoryEntry *build.AdvisoryContent
}

// Create creates a new advisory in the `advisories` section of the configuration
// at the provided path.
//

func Create(options CreateOptions) error {
	index := options.Index
	path := options.Pathname

	if count := index.Len(); count != 1 {
		return fmt.Errorf("can only operate on 1 config, but was given %d configs", count)
	}

	config, err := index.Get(configs.ByPath(path))
	if err != nil {
		// this would be unexpected, since we just created the index for this path, and it succeeded
		return fmt.Errorf("unable to find config for %q: %w", path, err)
	}

	vuln := options.Vuln
	advisoryEntry := options.InitialAdvisoryEntry
	if advisoryEntry == nil {
		return errors.New("cannot use nil advisory entry")
	}

	updaterFunc := NewConfigUpdaterForAdvisories(index, func(advisories build.Advisories) (build.Advisories, error) {
		if _, existsAlready := advisories[vuln]; existsAlready {
			return build.Advisories{}, fmt.Errorf("advisory already exists for %s", vuln)
		}

		advisories[vuln] = append(advisories[vuln], *advisoryEntry)

		return advisories, nil
	})

	err = index.Update(config, updaterFunc)
	if err != nil {
		return fmt.Errorf("unable to create advisories entry in %q: %w", path, err)
	}

	return nil
}

type UpdateOptions struct {
	// The Index of package configs on which to operate.
	Index *configs.Index

	// Pathname is the filepath for the configuration in which Update will append the
	// new advisory entry.
	Pathname string

	// Vuln is the vulnerability ID for the advisory to update.
	Vuln string

	// NewAdvisoryEntry is the entry that will be added to the advisory.
	NewAdvisoryEntry *build.AdvisoryContent
}

// Update adds a new entry to an existing advisory (named by the vuln parameter)
// in the configuration at the provided path.
//

func Update(options UpdateOptions) error {
	index := options.Index
	path := options.Pathname

	if count := index.Len(); count != 1 {
		return fmt.Errorf("can only update 1 config, but have %d configs", count)
	}

	config, err := index.Get(configs.ByPath(path))
	if err != nil {
		// this would be unexpected, since we just created the index for this path, and it succeeded
		return fmt.Errorf("unable to find config for %q: %w", path, err)
	}

	vuln := options.Vuln
	advisoryEntry := options.NewAdvisoryEntry
	if advisoryEntry == nil {
		return errors.New("cannot use nil advisory entry")
	}

	updaterFunc := NewConfigUpdaterForAdvisories(index, func(advisories build.Advisories) (build.Advisories, error) {
		if _, existsAlready := advisories[vuln]; !existsAlready {
			return build.Advisories{}, fmt.Errorf("no advisory exists for %s", vuln)
		}

		advisories[vuln] = append(advisories[vuln], *advisoryEntry)

		return advisories, nil
	})

	err = index.Update(config, updaterFunc)
	if err != nil {
		return fmt.Errorf("unable to add entry for advisory %q in %q: %w", vuln, path, err)
	}

	return nil
}

// Latest returns the latest entry among the given set of entries for an
// advisory. If there are no entries, Latest returns nil.
func Latest(entries []build.AdvisoryContent) *build.AdvisoryContent {
	if len(entries) == 0 {
		return nil
	}

	// Try to respect the caller's sort order, and make changes only in this scope.
	items := make([]build.AdvisoryContent, len(entries))
	copy(items, entries)

	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Timestamp.Before(items[j].Timestamp)
	})

	latestEntry := items[len(items)-1]
	return &latestEntry
}

func NewConfigUpdaterForAdvisories(i *configs.Index, transform func(build.Advisories) (build.Advisories, error)) configs.UpdateFunc {
	return i.NewUpdater(func(node *yaml.Node) error {
		advNode, err := yamlNodeForAdvisories(node)
		if err != nil {
			return err
		}

		advisories := build.Advisories{}
		err = advNode.Decode(&advisories)
		if err != nil {
			return err
		}

		updatedAdvisories, err := transform(advisories)
		if err != nil {
			return err
		}

		err = advNode.Encode(updatedAdvisories)
		if err != nil {
			return err
		}

		return nil
	})
}

func NewConfigUpdaterForSecfixes(i *configs.Index, transform func(secfixes build.Secfixes) (build.Secfixes, error)) configs.UpdateFunc {
	return i.NewUpdater(func(node *yaml.Node) error {
		sfNode, err := yamlNodeForSecfixes(node)
		if err != nil {
			return err
		}

		secfixes := build.Secfixes{}
		err = sfNode.Decode(&secfixes)
		if err != nil {
			return err
		}

		updatedSecfixes, err := transform(secfixes)
		if err != nil {
			return err
		}

		err = sfNode.Encode(updatedSecfixes)
		if err != nil {
			return err
		}

		return nil
	})
}

// yamlNodeForAdvisories locates and returns the yaml.Node within the provided
// AST for the `advisories` section, if one exists; otherwise, it creates the
// section, and returns a usable reference to the newly created section.
func yamlNodeForAdvisories(root *yaml.Node) (*yaml.Node, error) {
	const key = "advisories"
	return yamlNodeForKey(root, key)
}

// yamlNodeForSecfixes locates and returns the yaml.Node within the provided
// AST for the `secfixes` section, if one exists; otherwise, it creates the
// section, and returns a usable reference to the newly created section.
func yamlNodeForSecfixes(root *yaml.Node) (*yaml.Node, error) {
	const key = "secfixes"
	return yamlNodeForKey(root, key)
}

func yamlNodeForKey(root *yaml.Node, key string) (*yaml.Node, error) {
	rootMap := root.Content[0]

	iter := yit.FromNode(rootMap).ValuesForMap(yit.WithValue(key), yit.All)
	advNode, ok := iter()
	if ok {
		return advNode, nil
	}

	mapKey := &yaml.Node{Value: key, Tag: "!!str", Kind: yaml.ScalarNode}
	rootMap.Content = append(rootMap.Content, mapKey)
	mapValue := &yaml.Node{Tag: "!!map", Kind: yaml.MappingNode}
	rootMap.Content = append(rootMap.Content, mapValue)

	return mapValue, nil
}
