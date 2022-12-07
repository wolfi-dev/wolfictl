package main

import (
	"log"

	"github.com/wolfi-dev/wolfictl/pkg/cli"
)

func main() {
	if err := cli.New().Execute(); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
}
