package lint

import (
	"errors"

	"chainguard.dev/melange/pkg/config"
	"gopkg.in/yaml.v3"
)

// positionedError is an error attributed to a line of the configuration file
// being linted.
type positionedError struct {
	line int
	err  error
}

func (e *positionedError) Error() string { return e.err.Error() }

func (e *positionedError) Unwrap() error { return e.err }

// errorAt attributes err to the line of the configuration node found at path,
// see lineOf for how the path is resolved. If the line can't be determined, err
// is returned as is.
func errorAt(cfg config.Configuration, err error, path ...any) error {
	line := lineOf(cfg.Root(), path...)
	if line == 0 {
		return err
	}
	return &positionedError{line: line, err: err}
}

// errorLine returns the line attributed to err by errorAt, or 0 if there is
// none.
func errorLine(err error) int {
	var pe *positionedError
	if errors.As(err, &pe) {
		return pe.line
	}
	return 0
}

// lineOf returns the line of the node found by following path from root, where
// each element of path is either a mapping key (string) or a sequence index
// (int). The line of a mapping value is the line of its key, so that block
// values such as multi-line "runs" scripts point at the line naming them.
//
// When path can't be followed to the end, the line of the deepest node that
// was found is returned, so a missing key is reported at its parent. If not
// even the first element of path can be found, lineOf returns 0.
func lineOf(root *yaml.Node, path ...any) int {
	node := documentContent(root)

	line := 0
	for _, elem := range path {
		if node == nil {
			break
		}

		var next *yaml.Node
		switch elem := elem.(type) {
		case string:
			key, value := mappingEntry(node, elem)
			if key == nil {
				return line
			}
			line = key.Line
			next = value
		case int:
			if node.Kind != yaml.SequenceNode || elem < 0 || elem >= len(node.Content) {
				return line
			}
			next = node.Content[elem]
			line = next.Line
		}

		if next == nil {
			return line
		}
		node = next
	}

	return line
}

// subpackagePath returns the path to the raw YAML subpackage that produced
// cfg.Subpackages[i].
//
// The indexes of the parsed and raw subpackages differ when a subpackage uses a
// range, as melange expands it in place into one subpackage per item of the
// range's data.
func subpackagePath(cfg config.Configuration, i int) []any {
	path := []any{"subpackages"}

	root := documentContent(cfg.Root())
	_, subpackages := mappingEntry(root, "subpackages")
	if subpackages == nil || subpackages.Kind != yaml.SequenceNode {
		return path
	}

	// melange drops the data once ranges are expanded, so count the items of
	// each range from the raw YAML.
	rangeSizes := map[string]int{}
	if _, data := mappingEntry(root, "data"); data != nil && data.Kind == yaml.SequenceNode {
		for _, d := range data.Content {
			_, name := mappingEntry(d, "name")
			_, items := mappingEntry(d, "items")
			if name != nil && items != nil && items.Kind == yaml.MappingNode {
				rangeSizes[name.Value] = len(items.Content) / 2
			}
		}
	}

	expanded := 0
	for raw, sp := range subpackages.Content {
		count := 1
		if _, rng := mappingEntry(sp, "range"); rng != nil && rng.Value != "" {
			count = rangeSizes[rng.Value]
		}

		if i < expanded+count {
			return append(path, raw)
		}
		expanded += count
	}

	return path
}

// documentContent returns the top-level node of a YAML document node.
func documentContent(node *yaml.Node) *yaml.Node {
	if node != nil && node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return node.Content[0]
	}
	return node
}

// mappingEntry returns the key and value nodes of key in the mapping node, or
// nils if node isn't a mapping or doesn't contain key.
func mappingEntry(node *yaml.Node, key string) (keyNode, valueNode *yaml.Node) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i], node.Content[i+1]
		}
	}
	return nil, nil
}
