// Copyright © 2019 The Tekton Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"flag"
	"log"

	"github.com/wolfi-dev/wolfictl/pkg/cli"
)

func main() {
	var target string
	var kind string
	flag.StringVar(&target, "target", "/tmp", "Target path for generated yaml files")
	flag.StringVar(&kind, "kind", "markdown", "Kind of docs to generate (supported: man, markdown)")
	flag.Parse()

	log.Printf("Generating files into %s\n", target)

	root := cli.New()

	switch kind {
	case "markdown":
		if err := GenMarkdownTree(root, target); err != nil {
			log.Fatalf("Error generating markdown: %v\n", err)
		}
	case "man":
		if err := GenManTree(root, &GenManHeader{Section: "1"}, target); err != nil {
			log.Fatalf("Error generating man: %v\n", err)
		}
	default:
		log.Fatalf("invalid docs kind : %s", kind)
	}
}
