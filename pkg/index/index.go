package index

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/auth"
)

func Index(arch, repo string) (*apk.APKIndex, error) {
	var rc io.ReadCloser
	if strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "https://") {
		u, err := url.Parse(fmt.Sprintf("%s/%s/APKINDEX.tar.gz", repo, arch))
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		if err := auth.DefaultAuthenticators.AddAuth(context.TODO(), req); err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("GET %s (%d): %s", u.String(), resp.StatusCode, b)
		}
		rc = resp.Body
	} else {
		f, err := os.Open(repo)
		if err != nil {
			return nil, fmt.Errorf("opening %q: %w", repo, err)
		}
		defer f.Close()
		rc = f
	}

	return apk.IndexFromArchive(rc)
}
