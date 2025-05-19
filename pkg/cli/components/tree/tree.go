package tree

import (
	"errors"
	"strings"
)

// New returns a new Tree instance that's ready to be rendered.
//
// It takes two parameters: leaves and renderFunc. The resulting tree will have
// one leaf per element in the leaves slice, and each leaf's ancestors are
// inferred from the slice returned by the renderFunc. When the tree is
// rendered, the renderFunc is called once per leaf, and it's expected to return
// a slice of strings, each of which are rendered versions of the leaf's
// ancestors and the leaf itself.
//
// For example, let's say we use a leaves slice of []string{"ABC", "ABD", "BCD"}
// and a renderFunc implementation that returns a slice of the individual
// characters from the leaf string. The resulting tree would look like this:
//
//		 A
//		 └─ B
//			  C
//			  D
//		 B
//		 └─ C
//	          D
func New[T any](leaves []T, renderFunc LeafPathPartsRenderFunc[T]) (*Tree[T], error) {
	if renderFunc == nil {
		return nil, errors.New("renderFunc is required")
	}

	return &Tree[T]{
		leaves:     leaves,
		renderFunc: renderFunc,
	}, nil
}

// LeafPathPartsRenderFunc is a function that takes a leaf and returns a slice
// of strings. The strings are all the path parts from the root to the leaf.
// Each string is the rendered version of a path part.
type LeafPathPartsRenderFunc[T any] func(leaf T) []string

// NewStringSplitRenderFunc returns a LeafPathPartsRenderFunc that splits a
// string by the given separator.
//
// For example, if you use a separator of "/", the render function will split
// the leaf string by "/" and return the resulting slice.
func NewStringSplitRenderFunc(sep string) LeafPathPartsRenderFunc[string] {
	return func(leaf string) []string {
		return strings.Split(leaf, sep)
	}
}

type Tree[T any] struct {
	leaves     []T
	renderFunc LeafPathPartsRenderFunc[T]
}

// Render returns a string rendering of the tree.
func (t Tree[T]) Render() string {
	if len(t.leaves) == 0 {
		return ""
	}

	// Define a node type to build the tree structure
	type node struct {
		value    string
		children []*node
	}

	// Function to add a path to the tree, merging consecutive nodes as necessary
	var addPath func(n *node, path []string)
	addPath = func(n *node, path []string) {
		if len(path) == 0 {
			return
		}

		var child *node
		// Check only the last child for merging
		if len(n.children) > 0 {
			lastChild := n.children[len(n.children)-1]
			if lastChild.value == path[0] {
				child = lastChild
			}
		}

		// If the child doesn't exist or isn't the same, create it
		if child == nil {
			child = &node{value: path[0]}
			n.children = append(n.children, child)
		}

		// Recursively add the rest of the path
		addPath(child, path[1:])
	}

	// Root nodes of the tree
	var roots []*node

	// Build the tree by processing each leaf
	for _, leaf := range t.leaves {
		path := t.renderFunc(leaf)
		if len(path) == 0 {
			continue
		}

		// Add the path to the tree
		var root *node
		// Check only the last root for merging
		if len(roots) > 0 {
			lastRoot := roots[len(roots)-1]
			if lastRoot.value == path[0] {
				root = lastRoot
			}
		}

		// If the root doesn't exist or isn't the same, create it
		if root == nil {
			root = &node{value: path[0]}
			roots = append(roots, root)
		}

		// Add the rest of the path to the tree
		addPath(root, path[1:])
	}

	// Function to render the tree into a string
	var renderNode func(n *node, prefix string, level int, isLast bool) string
	renderNode = func(n *node, prefix string, level int, isLast bool) string {
		var sb strings.Builder

		indentation := "    " // Adjust indentation as needed

		// Write the node's value with appropriate indentation and prefix
		switch level {
		case 0:
			if n.value != "" {
				sb.WriteString(n.value)
				sb.WriteString("\n")
			}
		case 1:
			sb.WriteString(prefix)
			if isLast {
				sb.WriteString("└── ")
			} else {
				sb.WriteString("├── ")
			}
			sb.WriteString(n.value)
			sb.WriteString("\n")
		default:
			sb.WriteString(prefix)
			sb.WriteString(indentation)
			sb.WriteString(n.value)
			sb.WriteString("\n")
		}

		// Prepare the prefix for child nodes
		var childPrefix string
		switch level {
		case 0:
			// For root nodes, prefix is empty
			childPrefix = ""

		case 1:
			// For immediate children, adjust prefix
			if isLast {
				childPrefix = prefix + "    "
			} else {
				childPrefix = prefix + "│   "
			}

		default:
			// For deeper levels, maintain the current prefix
			childPrefix = prefix + indentation
		}

		// Render each child node
		for i, child := range n.children {
			sb.WriteString(renderNode(child, childPrefix, level+1, i == len(n.children)-1))
		}

		return sb.String()
	}

	// Build the final string by rendering each root node
	var sb strings.Builder
	for i, root := range roots {
		sb.WriteString(renderNode(root, "", 0, i == len(roots)-1))
	}

	return sb.String()
}
