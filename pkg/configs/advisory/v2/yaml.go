package v2

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// strictUnmarshal is a helper function that unmarshals a YAML node into a
// struct and returns an error if the node contains unknown fields.
//
// This function is useful because while the yaml.v3 package has a KnownFields
// option for its Decoder, this option doesn't cascade to nested nodes that have
// custom unmarshaling logic, which means the safety guaranteed at the root YAML
// node is not necessarily guaranteed at all children nodes. This is a known
// deficiency in the yaml.v3 library:
// https://github.com/go-yaml/yaml/issues/460.
//
// Note that this function will return an error if the node is empty. This is
// because the yaml.v3 library favors other unmarshal errors over unknown
// field errors, so there's no way to distinguish between an empty node and a
// node that contains unknown fields.
func strictUnmarshal[T any](n *yaml.Node) (*T, error) {
	by, err := yaml.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("intermediate marshaling node to bytes failed: %w", err)
	}

	buf := bytes.NewBuffer(by)
	dec := yaml.NewDecoder(buf)
	dec.KnownFields(true)

	data := new(T)
	err = dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to decode to Go type %T: %w",
			data,
			err,
		)
	}

	return data, nil
}
