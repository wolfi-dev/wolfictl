package index

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/chainguard-dev/go-apk/pkg/apk"
)

func Index(arch, repo string) (*apk.APKIndex, error) {
	var rc io.ReadCloser
	if strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "https://") {
		url := fmt.Sprintf("%s/%s/APKINDEX.tar.gz", repo, arch)
		resp, err := http.Get(url) //nolint:gosec
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("GET %s (%d): %s", url, resp.StatusCode, b)
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
