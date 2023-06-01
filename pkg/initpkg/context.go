package initpkg

import (
	"crypto/sha512"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	// apko_types "chainguard.dev/apko/pkg/build/types"
	melange_build "chainguard.dev/melange/pkg/build"
	melange_util "chainguard.dev/melange/pkg/util"
	yam "github.com/chainguard-dev/yam/pkg/yam/formatted"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Context struct {
	URI     string
	Name    string
	Version string
	License string
	Layout  string
	WorkDir string

	Build melange_build.Configuration
}

type Option func(*Context) error

// WithURI sets the URI used for fetching and analyzing source code
// to build a Melange recipe.
func WithURI(uri string) Option {
	return func(ctx *Context) error {
		ctx.URI = uri
		return nil
	}
}

// WithName overrides the name used for a package.
func WithName(name string) Option {
	return func(ctx *Context) error {
		ctx.Name = name
		return nil
	}
}

// WithVersion overrides the version used for a package.
func WithVersion(version string) Option {
	return func(ctx *Context) error {
		ctx.Version = version
		return nil
	}
}

// WithLicense overrides the license used for a package.
func WithLicense(license string) Option {
	return func(ctx *Context) error {
		ctx.License = license
		return nil
	}
}

// WithLayout overrides the Melange build strategy selected for
// a package.
func WithLayout(layout string) Option {
	return func(ctx *Context) error {
		ctx.Layout = layout
		return nil
	}
}

// New creates a new Context, which is used with Run.
func New(opts ...Option) (*Context, error) {
	ctx := Context{}

	for _, opt := range opts {
		if err := opt(&ctx); err != nil {
			return nil, err
		}
	}

	if ctx.URI == "" {
		return nil, fmt.Errorf("uri is not set")
	}

	return &ctx, nil
}

// InterpretGithub fills in package information for a GitHub project, and
// fetches the source, then synthesizes a git-checkout node on the Melange
// pipeline.
func (ctx *Context) InterpretGitHub(u *url.URL) error {
	rawURI := u.String()
	re := regexp.MustCompile(`https://github\.com/([^/]+)/([^/]+)`)

	match := re.FindStringSubmatch(rawURI)
	if len(match) != 3 {
		return fmt.Errorf("github project URI is malformed")
	}

	log.Printf("github repo owner: %s", match[1])
	log.Printf("package name: %s", match[2])

	return nil
}

// InterpretTarball fills in package information for a tarball, and fetches it,
// synthesizing a fetch node on the Melange pipeline.
func (ctx *Context) InterpretTarball(u *url.URL) error {
	rawURI := u.String()
	pattern := `([^\/]+)-([\d\.]+)\.(tar\.(gz|xz|bz2|lz|Z)|tgz|tbz2|txz|tlz)`

	re := regexp.MustCompile(pattern)
	if re == nil {
		return fmt.Errorf("unable to compile version regex")
	}

	match := re.FindStringSubmatch(rawURI)
	if len(match) < 3 {
		return fmt.Errorf("unable to deduce package identity from URL")
	}

	ctx.Build.Package.Name = match[1]
	ctx.Build.Package.Version = match[2]

	downloadedFile, err := melange_util.DownloadFile(rawURI)
	if err != nil {
		return fmt.Errorf("downloading sources: %w", err)
	}
	defer os.Remove(downloadedFile)

	expectedSHA512, err := melange_util.HashFile(downloadedFile, sha512.New())
	if err != nil {
		return fmt.Errorf("hashing sources: %w", err)
	}

	log.Printf("fetched source, hashed: %s", expectedSHA512)

	pipelineNode := melange_build.Pipeline{
		Uses: "fetch",
		With: map[string]string{
			"uri":             strings.ReplaceAll(rawURI, match[2], "${{package.version}}"),
			"expected-sha512": expectedSHA512,
		},
	}
	ctx.Build.Pipeline = append(ctx.Build.Pipeline, pipelineNode)

	unpacker, err := NewUnpacker(ctx)
	if err != nil {
		return fmt.Errorf("initializing unpacker: %w", err)
	}

	if err := unpacker.Unpack(downloadedFile); err != nil {
		return fmt.Errorf("unpacking sources: %w", err)
	}

	log.Printf("unpacked sources to %s", ctx.WorkDir)

	return nil
}

// InterpretURI interprets the provided source code URI and fills in project
// information as well as pipeline instructions in how to fetch the sources.
func (ctx *Context) InterpretURI(uri string) error {
	tarballSuffixes := []string{"tar", "tar.gz", "tar.xz", "tar.bz2", "tgz", "txz", "tbz2"}

	u, err := url.Parse(uri)
	if err != nil {
		return err
	}

	// TODO: Support using GitHub API to use git-checkout instead.
	// if u.Hostname() == "github.com" {
	//	return ctx.InterpretGitHub(u)
	// }

	for _, tarballSuffix := range tarballSuffixes {
		if strings.HasSuffix(u.Path, tarballSuffix) {
			return ctx.InterpretTarball(u)
		}
	}

	return fmt.Errorf("unable to interpret URI: no strategy found")
}

// Run is the main entrypoint and sets up a working directory, fetches the
// source code, analyzes it, and dumps a YAML build file.
func (ctx *Context) Run() error {
	log.Printf("attempting to make package from URI %s", ctx.URI)

	workDir, err := os.MkdirTemp("", "wolfictl-initpkg-*")
	if err != nil {
		return fmt.Errorf("creating working directory: %w", err)
	}
	defer os.RemoveAll(workDir)

	ctx.WorkDir = workDir
	log.Printf("working directory: %s", ctx.WorkDir)

	err = ctx.InterpretURI(ctx.URI)
	if err != nil {
		return err
	}

	ctx.Build.Package.Description = "TODO"
	ctx.Build.Environment.Contents.Packages = []string{"wolfi-baselayout", "busybox", "ca-certificates-bundle", "build-base"}

	// Determine licenses
	licenseTags, err := ctx.AnalyzeLicenses()
	if err != nil {
		return err
	}

	for _, licenseTag := range licenseTags {
		copyrightNode := melange_build.Copyright{
			License: licenseTag,
		}
		ctx.Build.Package.Copyright = append(ctx.Build.Package.Copyright, copyrightNode)
	}

	// Figure out how to build
	if err := ctx.AnalyzeLayout(); err != nil {
		return err
	}

	// Set up common subpackages
	docsSubpackage := melange_build.Subpackage{
		Name:        fmt.Sprintf("%s-doc", ctx.Build.Package.Name),
		Description: fmt.Sprintf("docs for %s", ctx.Build.Package.Name),
		Pipeline: []melange_build.Pipeline{{
			Uses: "split/manpages",
		}},
	}

	devSubpackage := melange_build.Subpackage{
		Name:        fmt.Sprintf("%s-dev", ctx.Build.Package.Name),
		Description: fmt.Sprintf("development files for %s", ctx.Build.Package.Name),
		Pipeline: []melange_build.Pipeline{{
			Uses: "split/dev",
		}},
	}

	ctx.Build.Subpackages = append(ctx.Build.Subpackages, devSubpackage, docsSubpackage)

	outFileName := fmt.Sprintf("%s.yaml", ctx.Build.Package.Name)
	outFile, err := os.Create(outFileName)
	if err != nil {
		return fmt.Errorf("opening package definition file for writing: %w", err)
	}
	defer outFile.Close()

	enc := yam.NewEncoder(outFile).AutomaticConfig()
	rootNode := &yaml.Node{}
	if err := rootNode.Encode(ctx.Build); err != nil {
		return err
	}

	if err := enc.Encode(rootNode); err != nil {
		return err
	}

	log.Printf("wrote %s", outFileName)
	log.Printf(" ")
	log.Printf("Please review %s and address all TODO items / comments.", outFileName)

	return nil
}
