package sbom

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/adrg/xdg"
	"github.com/anchore/syft/syft/sbom"
)

var sbomCacheDirectory = path.Join(xdg.CacheHome, "wolfictl", "sbom", "apk")

func cachedSBOMPath(inputFilePath string, f io.Reader) (string, error) {
	h := sha256.New()
	_, err := io.Copy(h, f)
	if err != nil {
		return "", fmt.Errorf("failed to hash input file: %w", err)
	}

	digest := h.Sum(nil)
	apkFilename := path.Base(inputFilePath)
	apkFilename = apkFilename[:len(apkFilename)-len(path.Ext(apkFilename))]

	return path.Join(sbomCacheDirectory, fmt.Sprintf("%s-sha256-%x.syft.json", apkFilename, digest)), nil
}

// CachedGenerate behaves similarly to Generate, but it caches the result of the
// SBOM generation using the user's local XDG cache home directory. Furthermore,
// if a generated SBOM is already available in the cache for the given APK,
// CachedGenerate will return the cached SBOM immediately instead of generating
// a new SBOM.
func CachedGenerate(inputFilePath string, f io.ReadSeeker, distroID string) (*sbom.SBOM, error) {
	// Check cache first

	cachedPath, err := cachedSBOMPath(inputFilePath, f)
	if err != nil {
		return nil, fmt.Errorf("failed to compute cached SBOM path: %w", err)
	}

	cached, err := os.Open(cachedPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to open cached SBOM for %q: %w", inputFilePath, err)
		}

		// Cache miss. Generate the SBOM.

		_, err := f.Seek(0, io.SeekStart)
		if err != nil {
			return nil, fmt.Errorf("failed to seek to start of input file: %w", err)
		}

		s, err := Generate(inputFilePath, f, distroID)
		if err != nil {
			return nil, fmt.Errorf("failed to generate SBOM: %w", err)
		}

		// Cache the new SBOM for retrieval later.

		err = os.MkdirAll(path.Dir(cachedPath), 0o755)
		if err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %w", err)
		}

		cached, err := os.Create(cachedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create cached SBOM file: %w", err)
		}
		defer cached.Close()

		jsonReader, err := ToSyftJSON(s)
		if err != nil {
			return nil, fmt.Errorf("failed to convert SBOM to Syft JSON: %w", err)
		}

		_, err = io.Copy(cached, jsonReader)
		if err != nil {
			return nil, fmt.Errorf("failed to write SBOM to cache: %w", err)
		}

		// Finally, return the SBOM.

		return s, nil
	}

	// Cache hit!

	defer cached.Close()
	s, err := FromSyftJSON(cached)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cached SBOM (%s): %w", cachedPath, err)
	}

	return s, nil
}
