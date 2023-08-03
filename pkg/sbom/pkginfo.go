package sbom

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"
)

const pkginfoPath = ".PKGINFO"

type pkgInfo struct {
	PkgName   string
	PkgVer    string
	Arch      string
	Size      int64
	Origin    string
	PkgDesc   string
	URL       string
	Commit    string
	License   string
	Depends   []string
	Provides  []string
	BuildTime time.Time
	DataHash  string
}

func parsePkgInfo(r io.Reader) (*pkgInfo, error) {
	// TODO: Use an upstream function to handle APK metadata parsing, such as
	//  https://gitlab.alpinelinux.org/alpine/go/-/blob/master/repository/package.go#L49.

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
		case "builddate":
			intValue, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				// We shouldn't raise an error because this isn't fatal. But we should warn the user.
				log.Printf("failed to parse build date %q: %s", value, err.Error())
			}
			info.BuildTime = time.Unix(intValue, 0).UTC()
		case "datahash":
			info.DataHash = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan: %w", err)
	}

	return info, nil
}
