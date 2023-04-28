package nvdapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

var _ vuln.Detector = (*Detector)(nil)

type Detector struct {
	client          *http.Client
	apiKey          string
	rateLimiter     *rate.Limiter
	serviceHost     string
	serviceEndpoint string
	packageToCPE    packageToCPE
}

func NewDetector(client *http.Client, serviceHost, apiKey string) *Detector {
	var rl *rate.Limiter
	if apiKey != "" {
		rl = rateLimiterWithAuth
	} else {
		rl = rateLimiterWithoutAuth
	}

	return &Detector{
		client:          client,
		apiKey:          apiKey,
		rateLimiter:     rl,
		serviceHost:     serviceHost,
		serviceEndpoint: CVEsEndpoint,
		packageToCPE:    cpeMappingRules,
	}
}

const (
	DefaultHost  = "services.nvd.nist.gov"
	CVEsEndpoint = "/rest/json/cves/2.0"
)

var (
	// The NVD API applies rate limits, and using an API key increases the limit.
	// For more information, see:
	// https://nvd.nist.gov/developers/start-here#rate-limits
	//
	// You'll notice we limit ourselves to just below the documented limit. This is
	// based on trial and error, and trying to minimize the chance of receiving HTTP
	// 403s from NVD, while still maximizing the rate of lookups.

	rateLimiterWithoutAuth = rate.NewLimiter(rate.Every(time.Second*30/3), 1)  // 5 reqs per 30 sec
	rateLimiterWithAuth    = rate.NewLimiter(rate.Every(time.Second*30/47), 1) // 50 reqs per 30 sec
)

// VulnerabilitiesForPackages uses CPE-based queries to the NVD API to detect
// vulnerability matches for the given list of packages. It returns a map of
// package names to slices of vulnerability matches for that package. This
// method's requests to the NVD API are constrained by the Detector's configured
// rate limiter.
func (s *Detector) VulnerabilitiesForPackages(ctx context.Context, packages ...string) (map[string][]vuln.Match, error) {
	matchesByPackage := make(map[string][]vuln.Match)
	matchesByPackageMutex := new(sync.Mutex) // avoid map concurrency issues

	g, ctx := errgroup.WithContext(ctx)

	for _, pkg := range packages {
		pkg := pkg // https://go.dev/doc/faq#closures_and_goroutines

		g.Go(func() error {
			matches, err := s.vulnerabilitiesForPackage(ctx, pkg)
			if err != nil {
				return err
			}

			if count := len(matches); count >= 1 {
				log.Printf("🤔 %s: potential CVE matches: %d", pkg, count)
			} else {
				log.Printf("😅 %s: no CVE matches returned", pkg)
			}

			matchesByPackageMutex.Lock()
			matchesByPackage[pkg] = matches
			matchesByPackageMutex.Unlock()

			return nil
		})
	}

	err := g.Wait()
	if err != nil {
		return nil, err
	}

	return matchesByPackage, nil
}

func (s *Detector) vulnerabilitiesForPackage(ctx context.Context, name string) ([]vuln.Match, error) {
	requestCPE := s.getCPE(name)

	var result []vuln.Match

	cves, err := s.doSearch(ctx, requestCPE)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic // (rangeValCopy) for readability
	for _, cve := range cves {
		cve := cve
		match, err := determineVulnMatch(&cve, name, requestCPE)
		if err != nil {
			return nil, err
		}
		if match == nil {
			continue
		}
		result = append(result, *match)
	}

	return result, nil
}

// determineVulnMatch looks at the Cve response data to determine whether
// there's a true match to the package. It returns an error if it can't produce
// a vuln.Match. It also outputs a nil vuln.Match in non-error scenarios if the
// Cve response data doesn't apply to the package.
func determineVulnMatch(cve *Cve, packageName, requestCPE string) (*vuln.Match, error) {
	// TODO: Should we only use the _first_ configuration, like secfixes-tracker does?

	// TODO: Consider dropping CVE matches for really old CVEs (because the
	//  data tends to be lower quality).

	if cve == nil {
		return nil, errors.New("input CVE was nil")
	}

	for _, configuration := range cve.Configurations {
		if configuration.Operator == "AND" {
			// For now, let's ignore AND-ed nodes. They usually mean that something is
			// running on a specific platform, which usually means it's not the software
			// we're looking for. E.g. https://nvd.nist.gov/vuln/detail/CVE-2009-3654.

			continue
		}

		for _, node := range configuration.Nodes {
			if node.Negate {
				// TODO: Decide what to do with this case and why.

				continue
			}

			for _, cpeMatch := range node.CpeMatch {
				if !cpeMatch.Vulnerable {
					continue
				}

				doCPEsMatch, err := cpeStringsMatch(requestCPE, cpeMatch.Criteria)
				if err != nil {
					return nil, err
				}
				if !doCPEsMatch {
					continue
				}

				vr, err := convertCpeMatchToVersionRange(cpeMatch)
				if err != nil {
					if errors.Is(err, errNoVersionData) {
						// skip — but we can reevaluate this decision in the future
						continue
					}
					return nil, err
				}

				m := vuln.Match{
					Package: vuln.Package{
						Name: packageName,
					},
					CPE: vuln.CPE{
						URI:          cpeMatch.Criteria,
						VersionRange: vr,
					},
					Vulnerability: vuln.Vulnerability{
						ID:  cve.ID,
						URL: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.ID),
					},
				}

				return &m, nil
			}
		}
	}

	return nil, nil
}

func cpeStringsMatch(requestCPE, responseCPE string) (bool, error) {
	req, err := wfn.Parse(requestCPE)
	if err != nil {
		return false, fmt.Errorf("cannot compare CPEs: %w", err)
	}
	resp, err := wfn.Parse(responseCPE)
	if err != nil {
		return false, fmt.Errorf("cannot compare CPEs: %w", err)
	}

	// Return "false" when the request CPE had no TargetSW set, but the response CPE
	// did have one set. This case usually means that the response CVE is for a
	// plugin or language-specific package. (For example, a Jenkins plugin.)
	if req.TargetSW == wfn.Any && resp.TargetSW != wfn.Any {
		return false, nil
	}

	return wfn.Match(req, resp), nil
}

var ErrRateLimited = errors.New("we've been rate limited by NVD! 🙊")

func (s *Detector) doSearch(ctx context.Context, cpe string) ([]Cve, error) {
	err := s.rateLimiter.Wait(ctx)
	if err != nil {
		return nil, err
	}

	// TODO: Deal with pages (not urgent because the default page size is 2,000
	//  CVEs, and we're searching for single packages at a time.)

	// TODO: Consider using an in-memory cache of API responses, keyed by the
	//  requested CPE. This would save time on redundant API requests, like searching
	//  for '...*:go...' multiple times because we've pruned versions from multiple,
	//  related packages like 'go-1.18', 'go-1.19', and 'go-1.20'.

	reqURL := fmt.Sprintf(
		"https://%s%s?virtualMatchString=%s",
		s.serviceHost,
		s.serviceEndpoint,
		cpe,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request with URL %q: %w", reqURL, err)
	}

	req.Header["Accept"] = []string{"application/json"}
	req.Header["User-Agent"] = []string{"wolfictl"}

	if k := s.apiKey; k != "" {
		req.Header["apiKey"] = []string{s.apiKey}
	}

	log.Printf("☎️  sending API request: %s", reqURL)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to complete request to URL %q: %w", reqURL, err)
	}
	if s := resp.StatusCode; s != http.StatusOK {
		if s == http.StatusForbidden || s == http.StatusTooManyRequests {
			return nil, ErrRateLimited
		}

		return nil, fmt.Errorf("got unexpected response status %d for request to %q. Headers: %+v", s, reqURL, resp.Header)
	}

	defer resp.Body.Close()

	var cvesResponse CVEsResponse
	if err := json.NewDecoder(resp.Body).Decode(&cvesResponse); err != nil {
		return nil, fmt.Errorf("unable to decode JSON response to URL %q: %w", reqURL, err)
	}

	cves := lo.Map(cvesResponse.Vulnerabilities, vulnerabilityToCve)

	return cves, nil
}

var errNoVersionData = errors.New("CPE has no version data available")

//nolint:gocritic // hugeParam
func convertCpeMatchToVersionRange(m CpeMatch) (vuln.VersionRange, error) {
	rawCPE := m.Criteria
	cpe, err := wfn.Parse(rawCPE)
	if err != nil {
		return vuln.VersionRange{}, fmt.Errorf("unable to parse CPE %q: %w", rawCPE, err)
	}

	if cpe.Version != wfn.Any {
		// The CPE URI itself specifies one specific version.

		return vuln.VersionRange{
			SingleVersion: cpe.Version,
		}, nil
	}

	vr := vuln.VersionRange{}

	if v := m.VersionStartIncluding; v != "" {
		vr.VersionRangeLowerInclusive = true
		vr.VersionRangeLower = v
	}

	if v := m.VersionEndIncluding; v != "" {
		vr.VersionRangeUpperInclusive = true
		vr.VersionRangeUpper = v
	} else if v := m.VersionEndExcluding; v != "" {
		vr.VersionRangeUpperInclusive = false
		vr.VersionRangeUpper = v
	}

	if vr.VersionRangeLower == "" && vr.VersionRangeUpper == "" {
		// No version data available! We'll consider this to be junk for now.
		return vuln.VersionRange{}, errNoVersionData
	}

	return vr, nil
}

func (s *Detector) getCPE(packageName string) string {
	// Chop off any version suffixes from package names like `clang-15` and `go-1.20`.
	if matches := regexWithVersionSuffix.FindStringSubmatch(packageName); len(matches) >= 2 {
		packageName = matches[1]
	}

	// Use a more precise CPE, if we have one. Otherwise, just create a CPE using
	// the package name as the 'product'.
	cpe, ok := s.packageToCPE[packageName]
	if !ok {
		cpe = wfn.Attributes{
			Product: packageName,
		}
	}

	// We're only interested in "application" CPEs, not:
	//	- "o": operating systems
	//	- "h": hardware devices
	cpe.Part = "a"

	cpe = handleCPELanguage(cpe)

	return cpe.BindToFmtString()
}

var regexWithVersionSuffix = regexp.MustCompile(`(?U)(.+)(-\d+(\.\d+)*)?$`)

type packageToCPE map[string]wfn.Attributes

// cpeMappingRules ...
//
// TODO: make these rules driven by a config file
var cpeMappingRules packageToCPE = map[string]wfn.Attributes{
	"cortex": {
		Vendor:  "linuxfoundation",
		Product: "cortex",
	},
	"curl": {
		Vendor:  "haxx",
		Product: "curl",
	},
	"envoy": {
		Vendor:  "envoyproxy",
		Product: "envoy",
	},
	"exim": {
		Vendor:  "exim",
		Product: "exim",
	},
	"flex": {
		Vendor:  "flex_project",
		Product: "flex",
	},
	"git": {
		Vendor:  "git-scm",
		Product: "git",
	},
	"jenkins": {
		Vendor:  "jenkins",
		Product: "jenkins",
	},
	"memcached": {
		Vendor:  "memcached",
		Product: "memcached",
	},
	"openjdk": {
		Vendor:  "oracle",
		Product: "openjdk",
	},
	"php": {
		Vendor:  "php",
		Product: "php",
	},
	"redis": {
		Vendor:  "redis",
		Product: "redis",
	},
	"vault": {
		Vendor:  "hashicorp",
		Product: "vault",
	},
}

var productLanguageMappings = []struct {
	productPrefix string
	cpeTargetSW   string
}{
	{productPrefix: "py3-", cpeTargetSW: "python"},
	{productPrefix: "py3.10-", cpeTargetSW: "python"},
	{productPrefix: "py3.11-", cpeTargetSW: "python"},
	{productPrefix: "ruby-", cpeTargetSW: "ruby"},
	{productPrefix: "ruby3.0-", cpeTargetSW: "ruby"},
	{productPrefix: "ruby3.1-", cpeTargetSW: "ruby"},
	{productPrefix: "ruby3.2-", cpeTargetSW: "ruby"},
	{productPrefix: "perl-", cpeTargetSW: "perl"},
	{productPrefix: "lua-", cpeTargetSW: "lua"},
	{productPrefix: "vscode-", cpeTargetSW: "visual_studio_code"},
}

//nolint:gocritic // hugeParam
func handleCPELanguage(cpe wfn.Attributes) wfn.Attributes {
	for _, m := range productLanguageMappings {
		if strings.HasPrefix(cpe.Product, m.productPrefix) {
			cpe.Product = strings.TrimPrefix(cpe.Product, m.productPrefix)
			cpe.TargetSW = m.cpeTargetSW
			return cpe
		}
	}

	return cpe
}
