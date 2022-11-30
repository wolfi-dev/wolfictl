package main

import (
	"github.com/wolfi-dev/wolfictl/pkg/cli"
	"log"
)

func main() {
	if err := cli.New().Execute(); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
}
