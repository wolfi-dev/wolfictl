package gomod

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"go.opentelemetry.io/otel"
)

// Repo returns the source code repository URL for the given module import path.
func Repo(ctx context.Context, importpath string) (string, error) {
	_, span := otel.Tracer("wolfictl").Start(ctx, fmt.Sprintf("resolving git URL for go module %s", importpath))
	defer span.End()

	if strings.HasPrefix(importpath, "github.com/") {
		trimmed := trimMajorVersionSuffix(importpath)
		return "https://" + trimmed, nil
	}

	resp, err := http.Get("https://" + importpath + "?go-get=1")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	metas, err := parseMetaGoImports(resp.Body)
	if err != nil {
		return "", err
	}
	return metas[0].RepoRoot, nil
}

var majorVersionSuffixRegex = regexp.MustCompile(`/v\d+$`)

func trimMajorVersionSuffix(v string) string {
	return majorVersionSuffixRegex.ReplaceAllString(v, "")
}
