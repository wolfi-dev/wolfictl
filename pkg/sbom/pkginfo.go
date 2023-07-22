package sbom

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const pkginfoPath = ".PKGINFO"

type pkgInfo struct {
	PkgName  string
	PkgVer   string
	Arch     string
	Size     int64
	Origin   string
	PkgDesc  string
	URL      string
	Commit   string
	License  string
	Depends  []string
	Provides []string
	DataHash string
}

func parsePkgInfo(r io.Reader) (*pkgInfo, error) {
	info := &pkgInfo{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		// ignore comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, " = ", 2)
		if len(parts) != 2 {
			continue
		}

		// strip whitespaces
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "pkgname":
			info.PkgName = value
		case "pkgver":
			info.PkgVer = value
		case "arch":
			info.Arch = value
		case "size":
			// assuming that size is an int
			size, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse size: %w", err)
			}
			info.Size = size
		case "origin":
			info.Origin = value
		case "pkgdesc":
			info.PkgDesc = value
		case "url":
			info.URL = value
		case "commit":
			info.Commit = value
		case "license":
			info.License = value
		case "depend":
			info.Depends = append(info.Depends, value)
		case "provides":
			info.Provides = append(info.Provides, value)
		case "datahash":
			info.DataHash = value
		default:
			fmt.Printf("Unknown key: %s\n", key)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan: %w", err)
	}

	return info, nil
}
