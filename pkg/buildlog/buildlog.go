package buildlog

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// DefaultName is the default name used for a Melange build log file.
const DefaultName = "packages.log"

// Entry represents a single line in a Melange build log.
type Entry struct {
	Arch, Origin, Package, FullVersion string
}

// Parse parses a Melange build log into a slice of entries.
func Parse(r io.Reader) ([]Entry, error) {
	splitFunc := func(ru rune) bool {
		return string(ru) == "|"
	}

	var entries []Entry

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.FieldsFunc(line, splitFunc)
		if len(fields) != 4 {
			return nil, fmt.Errorf("invalid line %q, expected 4 '|'-delimited fields", line)
		}

		entry := Entry{
			Arch:        fields[0],
			Origin:      fields[1],
			Package:     fields[2],
			FullVersion: fields[3],
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning lines of build log: %w", err)
	}

	return entries, nil
}
