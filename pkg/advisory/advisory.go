package advisory

import (
	"fmt"
	"sort"

	"chainguard.dev/melange/pkg/build"
	"github.com/dprotaso/go-yit"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"gopkg.in/yaml.v3"
)

// Create creates a new advisory in the `advisories` section of the configuration
// at the provided path.
func Create(configPath string, vuln string, initialAdvisoryEntry build.AdvisoryContent) error {
	index, err := configs.NewIndexFromPaths(configPath)
	if err != nil {
		return err
	}

	config, err := index.Get(configs.ByPath(configPath))
	if err != nil {
		// this would be unexpected, since we just created the index for this path, and it succeeded
		return fmt.Errorf("unable to find config for %q: %w", configPath, err)
	}

	updaterFunc := NewConfigUpdaterForAdvisories(index, func(advisories build.Advisories) (build.Advisories, error) {
		if _, existsAlready := advisories[vuln]; existsAlready {
			return build.Advisories{}, fmt.Errorf("advisory already exists for %s", vuln)
		}

		advisories[vuln] = append(advisories[vuln], initialAdvisoryEntry)

		return advisories, nil
	})

	err = index.Update(config, updaterFunc)
	if err != nil {
		return fmt.Errorf("unable to create advisories entry in %q: %w", configPath, err)
	}

	return nil
}

// Update adds a new entry to an existing advisory (named by the vuln parameter)
// in the configuration at the provided path.
func Update(configPath string, vuln string, newAdvisoryEntry build.AdvisoryContent) error {
	index, err := configs.NewIndexFromPaths(configPath)
	if err != nil {
		return err
	}

	config, err := index.Get(configs.ByPath(configPath))
	if err != nil {
		// this would be unexpected, since we just created the index for this path, and it succeeded
		return fmt.Errorf("unable to find config for %q: %w", configPath, err)
	}

	updaterFunc := NewConfigUpdaterForAdvisories(index, func(advisories build.Advisories) (build.Advisories, error) {
		if _, existsAlready := advisories[vuln]; !existsAlready {
			return build.Advisories{}, fmt.Errorf("no advisory exists for %s", vuln)
		}

		advisories[vuln] = append(advisories[vuln], newAdvisoryEntry)

		return advisories, nil
	})

	err = index.Update(config, updaterFunc)
	if err != nil {
		return fmt.Errorf("unable to create advisories entry in %q: %w", configPath, err)
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
