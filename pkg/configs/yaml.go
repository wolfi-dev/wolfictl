package configs

import (
	"errors"
	"fmt"

	"github.com/chainguard-dev/yam/pkg/yam/formatted"
	"github.com/dprotaso/go-yit"
	"gopkg.in/yaml.v3"
)

// A YAMLASTMutater is a function that mutates a YAML AST. The function is also
// given a configuration struct (type T) in case implementations require it for
// context.
type YAMLASTMutater[T any] func(T, *yaml.Node) error

// NewYAMLUpdateFunc returns a EntryUpdater function that will use the
// YAMLASTMutater provided to operate on a given Entry.
func NewYAMLUpdateFunc[T Configuration](yamlASTMutater YAMLASTMutater[T]) EntryUpdater[T] {
	return func(i *Index[T], e Entry[T]) error {
		root := e.yamlASTRoot()

		cfg := e.Configuration()
		if cfg == nil {
			return errors.New("nil configuration")
		}

		err := yamlASTMutater(*cfg, root)
		if err != nil {
			return err
		}

		file, err := i.fsys.OpenAsWritable(e.getPath())
		if err != nil {
			return fmt.Errorf("unable to update %q: %w", e.getPath(), err)
		}
		defer file.Close()

		err = i.fsys.Truncate(e.getPath(), 0)
		if err != nil {
			return fmt.Errorf("unable to update %q: %w", e.getPath(), err)
		}

		encoder := formatted.NewEncoder(file).AutomaticConfig()

		err = encoder.Encode(root)
		if err != nil {
			return fmt.Errorf("unable to encode updated YAML: %w", err)
		}

		return nil
	}
}

func yamlNodeForKey(root *yaml.Node, key string) *yaml.Node {
	rootMap := root.Content[0]

	iter := yit.FromNode(rootMap).ValuesForMap(yit.WithValue(key), yit.All)
	advNode, ok := iter()
	if ok {
		return advNode
	}

	mapKey := &yaml.Node{Value: key, Tag: "!!str", Kind: yaml.ScalarNode}
	rootMap.Content = append(rootMap.Content, mapKey)
	mapValue := &yaml.Node{Tag: "!!map", Kind: yaml.MappingNode}
	rootMap.Content = append(rootMap.Content, mapValue)

	return mapValue
}
