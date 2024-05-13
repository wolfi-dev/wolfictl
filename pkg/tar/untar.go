package tar

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Untar should be named Untargz.
func Untar(src io.Reader, dst string) error {
	zr, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)

	// uncompress each element
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break // End of archive
		}
		if err != nil {
			return err
		}

		target, err := sanitizeArchivePath(dst, header.Name)
		// validate name against path traversal
		if err != nil {
			return err
		}

		// check the type
		switch header.Typeflag {
		// Create directories
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, os.ModePerm); err != nil {
					return err
				}
			}
		// Write out files
		case tar.TypeReg:
			// Ensure the parent directory exists
			if err := os.MkdirAll(filepath.Dir(target), os.ModePerm); err != nil {
				return err
			}
			fileToWrite, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			// copy over contents in chunks for security reasons
			// G110: Potential DoS vulnerability via decompression bomb
			for {
				_, err := io.CopyN(fileToWrite, tr, 1024)
				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return err
				}
			}

			if err := fileToWrite.Close(); err != nil {
				return fmt.Errorf("failed to close file %s: %w", target, err)
			}
		}
	}
	return nil
}

// From https://github.com/securego/gosec/issues/324
func sanitizeArchivePath(d, t string) (string, error) {
	// Convert to forward slashes
	cleanedTarget := filepath.FromSlash(t)

	v := filepath.Join(d, cleanedTarget)
	cleanedBase := filepath.Clean(d)

	if strings.HasPrefix(v, cleanedBase) {
		return v, nil
	}

	return "", fmt.Errorf("%s: %s", "content filepath is tainted", t)
}
