package initpkg

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/ulikunitz/xz"
)

type Unpacker struct {
	Context *Context
}

// NewUnpacker returns a new unpacker context.
func NewUnpacker(ctx *Context) (*Unpacker, error) {
	unpacker := Unpacker{
		Context: ctx,
	}

	return &unpacker, nil
}

type DecompressStrategy func(r io.ReadSeeker) (io.Reader, error)

func decompressXz(par io.ReadSeeker) (io.Reader, error) {
	r, err := xz.NewReader(par)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func decompressGzip(par io.ReadSeeker) (io.Reader, error) {
	r, err := gzip.NewReader(par)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func decompressBzip2(par io.ReadSeeker) (io.Reader, error) {
	// bzip2.NewReader does not perform header validation, so we must
	// do it ourselves.  Sigh.
	magicBuf := make([]byte, 2)
	if _, err := io.ReadFull(par, magicBuf); err != nil {
		return nil, err
	}

	if !bytes.Equal(magicBuf, []byte{'B', 'Z'}) {
		return nil, fmt.Errorf("invalid bzip2 header")
	}

	if _, err := par.Seek(io.SeekStart, 0); err != nil {
		return nil, fmt.Errorf("rewinding file: %w", err)
	}

	return bzip2.NewReader(par), nil
}

// Unpack attempts to unpack an archive.
func (u *Unpacker) Unpack(sourceFile string) error {
	f, err := os.Open(sourceFile)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	decomps := map[string]DecompressStrategy{
		"xz":    decompressXz,
		"gzip":  decompressGzip,
		"bzip2": decompressBzip2,
	}

	var decompReader io.Reader
	for decompType, decomp := range decomps {
		if _, err := f.Seek(io.SeekStart, 0); err != nil {
			return fmt.Errorf("rewinding file: %w", err)
		}

		r, err := decomp(f)
		if err != nil {
			continue
		}

		log.Printf("using %s decompressor", decompType)
		decompReader = r
		break
	}

	if decompReader == nil {
		return fmt.Errorf("no unpacking strategy found")
	}

	if err := u.untar(decompReader); err != nil {
		return fmt.Errorf("unpacking tar: %w", err)
	}

	return nil
}

func (u *Unpacker) untar(r io.Reader) error {
	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()

		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		}

		nameComponents := strings.Split(header.Name, "/")

		if len(nameComponents) < 2 {
			continue
		}
		newName := filepath.Join(nameComponents[1:]...)

		target := filepath.Join(u.Context.WorkDir, newName)

		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}

		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			if _, err := io.Copy(f, tr); err != nil {
				return err
			}

			f.Close()

		default:
			continue
		}
	}
}
