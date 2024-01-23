package ruby

import (
	"path"

	"github.com/adrg/xdg"
	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
)

type RubyOptions struct {
	// RubyVersion is the version of Ruby to search for within the wolfi
	// directory. Used to search for packages importing ruby-${RubyVersion}
	RubyVersion string

	// RubyUpdateVersion is the version of Ruby to update to
	RubyUpdateVersion string

	// Github code search string
	SearchTerm string

	// Path is the path to the wolfi directory or a single package to check
	Path string

	// Client is the client used to communicate with Github
	Client *http2.RLHTTPClient

	// NoCache instructs the client to not use cached results
	NoCache bool
}

const (
	rubyKey                = "ruby-"
	rubyVersionKey         = "required_ruby_version"
	gemspecSuffix          = ".gemspec"
	requiredRubyVersionKey = "required_ruby_version"
)

var rubyCacheDirectory = path.Join(xdg.CacheHome, "wolfictl", "ruby")

type RubyContext struct {
	Pkg           RubyPackage
	UpdateVersion string
	Client        *http2.RLHTTPClient
}
