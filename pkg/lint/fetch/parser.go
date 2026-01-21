package fetch

import (
	"gopkg.in/yaml.v3"
)

// Searches for a key in a YAML mapping node
func findYamlValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(mapping.Content); i += 2 {
		if i+1 < len(mapping.Content) && mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

// Extracts a string value from a YAML mapping node
func getYamlString(mapping *yaml.Node, key string) string {
	if node := findYamlValue(mapping, key); node != nil && node.Kind == yaml.ScalarNode {
		return node.Value
	}
	return ""
}

// Recursively processes pipeline steps to extract source data
func processPipelineSteps(pipelineSeq *yaml.Node, sources *sourceData) {
	if pipelineSeq == nil || pipelineSeq.Kind != yaml.SequenceNode {
		return
	}

	for _, step := range pipelineSeq.Content {
		if step.Kind != yaml.MappingNode {
			continue
		}

		uses := getYamlString(step, "uses")
		withNode := findYamlValue(step, "with")

		if uses == "fetch" && withNode != nil {
			if uri := getYamlString(withNode, "uri"); uri != "" {
				sources.fetchURLs = append(sources.fetchURLs, uri)
			}
		}

		if uses == "git-checkout" && withNode != nil {
			if tag := getYamlString(withNode, "tag"); tag != "" {
				sources.gitTags = append(sources.gitTags, tag)
			}

			if ref := getYamlString(withNode, "ref"); ref != "" {
				sources.gitBranches = append(sources.gitBranches, gitRefInfo{
					Ref: ref,
				})
			}
		}

		// Handle nested pipelines in "with" blocks
		if withNode != nil {
			if nestedPipeline := findYamlValue(withNode, "pipeline"); nestedPipeline != nil {
				processPipelineSteps(nestedPipeline, sources)
			}
		}

		// Handle direct nested pipelines
		if nestedPipeline := findYamlValue(step, "pipeline"); nestedPipeline != nil {
			processPipelineSteps(nestedPipeline, sources)
		}
	}
}

// Extracts fetch sources and git data from raw YAML before template substitution
func extractRawPipelineData(root *yaml.Node) sourceData {
	sources := sourceData{}

	if root == nil {
		return sources
	}

	// Unwrap DocumentNode to get content
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}

	if root.Kind == yaml.MappingNode {
		if mainPipeline := findYamlValue(root, "pipeline"); mainPipeline != nil {
			processPipelineSteps(mainPipeline, &sources)
		}

		if subpackages := findYamlValue(root, "subpackages"); subpackages != nil && subpackages.Kind == yaml.SequenceNode {
			for _, subpkg := range subpackages.Content {
				if subPipeline := findYamlValue(subpkg, "pipeline"); subPipeline != nil {
					processPipelineSteps(subPipeline, &sources)
				}
			}
		}
	}

	return sources
}
