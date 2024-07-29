package update

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"chainguard.dev/melange/pkg/config"
	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
	"golang.org/x/exp/maps"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

type Options struct {
	PackageConfigs         map[string]*melange.Packages
	ReleaseMonitoringQuery bool
	GithubReleaseQuery     bool
	ReleaseMonitorClient   *http2.RLHTTPClient
	Logger                 *log.Logger
	GitHubHTTPClient       *http2.RLHTTPClient
	ErrorMessages          map[string]string

	PkgPath          string
	PackagesToUpdate map[string]NewVersionResults
}

type NewVersionResults struct {
	Version string
	Commit  string
}

// New initialise including a map of existing wolfios packages
func New(ctx context.Context) Options {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	token := os.Getenv("RELEASE_MONITOR_TOKEN")

	var rateLimitDuration time.Duration
	if token == "" {
		rateLimitDuration = 5 * time.Second
	} else {
		rateLimitDuration = 1 * time.Second / 2
	}

	client := &http.Client{
		Transport: &CustomTransport{
			Transport: http.DefaultTransport,
			Token:     token,
		},
	}

	options := Options{
		ReleaseMonitorClient: &http2.RLHTTPClient{
			Client:      client,
			Ratelimiter: rate.NewLimiter(rate.Every(rateLimitDuration), 1),
		},

		GitHubHTTPClient: &http2.RLHTTPClient{
			Client: oauth2.NewClient(ctx, ts),

			// 1 request every (n) second(s) to avoid DOS'ing server. https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
			Ratelimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
		},
		Logger:        log.New(log.Writer(), "wolfictl update: ", log.LstdFlags|log.Lmsgprefix),
		ErrorMessages: make(map[string]string),
	}
	return options
}

func (o *Options) GetLatestVersions(ctx context.Context, dir string, packageNames []string) (map[string]NewVersionResults, error) {
	var err error
	latestVersions := make(map[string]NewVersionResults)

	// first, let's get the melange package(s) from the target git repo, that we want to check for updates
	o.PackageConfigs, err = melange.ReadPackageConfigs(ctx, packageNames, filepath.Join(dir, o.PkgPath))
	if err != nil {
		return nil, fmt.Errorf("failed to get package configs: %w", err)
	}

	// remove any updates that have been disabled
	for i := range o.PackageConfigs {
		c := o.PackageConfigs[i]
		if !c.Config.Update.Enabled {
			delete(o.PackageConfigs, i)
		}
	}

	if len(o.PackageConfigs) == 0 {
		o.Logger.Printf("no package updates")
		return nil, nil
	}

	if o.GithubReleaseQuery {
		// let's get any versions that use GITHUB first as we can do that using reduced graphql requests
		g := NewGitHubReleaseOptions(o.PackageConfigs, o.GitHubHTTPClient)
		v, errorMessages, err := g.getLatestGitHubVersions()
		if err != nil {
			return latestVersions, fmt.Errorf("failed getting github releases: %w", err)
		}
		maps.Copy(o.ErrorMessages, errorMessages)
		maps.Copy(latestVersions, v)
	}

	if o.ReleaseMonitoringQuery {
		// get latest versions from https://release-monitoring.org/
		m := MonitorService{
			Client: o.ReleaseMonitorClient,
			Logger: o.Logger,
		}
		v, errorMessages := m.getLatestReleaseMonitorVersions(o.PackageConfigs)
		if err != nil {
			return nil, fmt.Errorf("failed release monitor versions: %w", err)
		}
		maps.Copy(o.ErrorMessages, errorMessages)
		maps.Copy(latestVersions, v)
	}

	return latestVersions, nil
}

// if provided, transform the version using the update config
func transformVersion(c config.Update, v string) (string, error) {
	if len(c.VersionTransform) == 0 {
		return v, nil
	}

	mutatedVersion := v

	for _, tf := range c.VersionTransform {
		matcher, err := regexp.Compile(tf.Match)
		if err != nil {
			return v, fmt.Errorf("unable to compile version transform regex: %w", err)
		}

		mutatedVersion = matcher.ReplaceAllString(mutatedVersion, tf.Replace)
	}

	return mutatedVersion, nil
}
