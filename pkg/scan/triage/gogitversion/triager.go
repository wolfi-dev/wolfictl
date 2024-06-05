package gogitversion

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/pkg"
	"github.com/chainguard-dev/clog"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/internal/gomod"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
	"github.com/wolfi-dev/wolfictl/pkg/scan/triage"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
	"go.opentelemetry.io/otel"
)

type Triager struct {
	repositoriesCacheDir string
	grypeVulnProvider    vulnerability.Provider

	// moduleToGitURL lets us cache the git URLs we resolve from Go module names.
	moduleToGitURL map[string]string

	// gitURLToRepo is a map of git URLs to their git.Repository objects. This lets
	// us open each repo exactly once per session. This also helps signal to the
	// code in this object that the repository has already been refreshed (pulled or
	// cloned) this session and is ready to use.
	gitURLToRepo map[string]*git.Repository

	// repoVersionToCommit is a map of git repository URLs to a map of module
	// versions to the commit that version corresponds to.
	repoVersionToCommit map[string]map[string]*object.Commit

	// isAncestorCache is a map of commit hashes to whether the fixed commit is an
	// ancestor of the installed commit.
	isAncestorCache map[commitHashes]bool

	// vulnerabilityIDToModuleNameToCommits is a map of vulnerability IDs to a map of
	// module names to the installed and fixed commits for that vulnerability and
	// module.
	vulnerabilityIDToModuleNameToCommits map[string]map[string]commits

	// commitToTags is a map of commit hashes to the tag(s) that correspond to that
	// commit.
	commitToTags map[string][]string
}

type TriagerOptions struct {
	RepositoriesCacheDir       string
	GrypeVulnerabilityProvider vulnerability.Provider
}

func New(opts TriagerOptions) *Triager {
	return &Triager{
		repositoriesCacheDir:                 opts.RepositoriesCacheDir,
		grypeVulnProvider:                    opts.GrypeVulnerabilityProvider,
		repoVersionToCommit:                  make(map[string]map[string]*object.Commit),
		gitURLToRepo:                         make(map[string]*git.Repository),
		moduleToGitURL:                       make(map[string]string),
		vulnerabilityIDToModuleNameToCommits: make(map[string]map[string]commits),
		isAncestorCache:                      make(map[commitHashes]bool),
		commitToTags:                         make(map[string][]string),
	}
}

type isAncestorReason struct {
	installedCommit string
	fixedCommit     string
	isAncestor      bool
	location        string
	moduleName      string
}

type commitHasTagOfLaterVersionReason struct {
	installedCommit    string
	installedCommitTag string
	fixedVersion       string
	location           string
	moduleName         string
}

type commits struct {
	installed *object.Commit
	fixed     *object.Commit
}

type commitHashes struct {
	installed string
	fixed     string
}

const grypeDBNamespaceForGitHubGo = "github:language:go"

func (t *Triager) Triage(ctx context.Context, vfs scan.VulnFindings) (*advisory.Request, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, fmt.Sprintf("gogitversion triage %s in %s", vfs.VulnerabilityID, vfs.TargetAPK.Name))
	defer span.End()

	logger := clog.FromContext(ctx)
	logger = logger.With("triager", "gogitversion")
	logger.Info("triaging", "vulnerabilityID", vfs.VulnerabilityID, "targetAPK", vfs.TargetAPK.Name, "targetAPKVersion", vfs.TargetAPK.Version, "cacheDir", t.repositoriesCacheDir)

	conclusions := make([]triage.Conclusion, len(vfs.Findings))

	for i := range vfs.Findings {
		finding := vfs.Findings[i]

		if finding.Package.Type != string(pkg.GoModulePkg) {
			return nil, fmt.Errorf("%s (at %s) is not a Go module: %w", finding.Package.Name, finding.Package.Location, triage.ErrNoConclusion)
		}

		moduleName := finding.Package.Name

		if finding.Vulnerability.FixedVersion == "" {
			logger.Debug("no fixed version in scanner finding", "vulnerabilityID", vfs.VulnerabilityID, "moduleName", moduleName)

			// NOTE: This is an *experimental* workaround for the fact that Grype sometimes
			// doesn't provide a fixed version for vulnerabilities, if there are multiple
			// "fixed" version ranges in its database and the original vulnerability
			// scanning selected a non-fixed range. It'd be better to avoid using Grype's
			// database for fixed versions ALWAYS, deferring instead to an upstream data
			// source like GHSA.

			vs, err := t.grypeVulnProvider.Get(finding.Vulnerability.ID, grypeDBNamespaceForGitHubGo)
			if err != nil {
				return nil, fmt.Errorf("getting vulnerability details for %q from Grype: %w", finding.Vulnerability.ID, err)
			}

			var newFixedVersion string
			for i := range vs {
				v := vs[i]

				if v.ID != finding.Vulnerability.ID || v.Fix.State != v5.FixedState {
					continue
				}

				if len(v.Fix.Versions) != 1 {
					continue
				}

				newFixedVersion = v.Fix.Versions[0]
				break
			}

			if newFixedVersion == "" {
				// Oh well, it was worth a shot!
				continue
			}

			logger.Warn("swapping in new fixed version from Grype database", "vulnerabilityID", finding.Vulnerability.ID, "moduleName", moduleName, "newFixedVersion", newFixedVersion)
			finding.Vulnerability.FixedVersion = newFixedVersion
		}

		cs, err := t.resolveCommits(ctx, finding)
		if err != nil {
			logger.Warn("unable to resolve fixed and/or installed commit for finding", "vulnerabilityID", vfs.VulnerabilityID, "moduleName", moduleName, "error", err)
			continue
		}

		// Check if the fixed commit is an ancestor of the installed commit
		isAncestor, err := t.isAncestor(ctx, cs.fixed, cs.installed)
		if err != nil {
			return nil, err
		}

		if isAncestor {
			c := triage.Conclusion{
				Type: triage.FalsePositive,
				Reason: isAncestorReason{
					installedCommit: cs.installed.Hash.String(),
					fixedCommit:     cs.fixed.Hash.String(),
					isAncestor:      isAncestor,
					location:        finding.Package.Location,
					moduleName:      moduleName,
				},
			}
			conclusions[i] = c
			continue
		}

		// Check if the installed commit corresponds to a semver tag, and if that tag is
		// later than the fixed version.

		tag, err := t.checkInstalledCommitForTagLaterThanFixedVersion(ctx, moduleName, cs.installed, finding.Vulnerability.FixedVersion)
		if err != nil {
			return nil, fmt.Errorf("checking installed commit for tag later than fixed version: %w", err)
		}

		if tag == "" {
			continue
		}

		c := triage.Conclusion{
			Type: triage.FalsePositive,
			Reason: commitHasTagOfLaterVersionReason{
				installedCommit:    cs.installed.Hash.String(),
				installedCommitTag: tag,
				fixedVersion:       finding.Vulnerability.FixedVersion,
				location:           finding.Package.Location,
				moduleName:         moduleName,
			},
		}
		conclusions[i] = c
	}

	event := eventFromConclusions(conclusions)

	if event == nil {
		logger.Info("no conclusion reached", "vulnerabilityID", vfs.VulnerabilityID)
		return nil, triage.ErrNoConclusion
	}

	logger.Info("found false positive", "vulnerabilityID", vfs.VulnerabilityID)

	return &advisory.Request{
		Package:         vfs.TargetAPK.OriginPackageName,
		VulnerabilityID: vfs.VulnerabilityID,
		Event:           *event,
	}, nil
}

func (t *Triager) checkInstalledCommitForTagLaterThanFixedVersion(ctx context.Context, moduleName string, installedCommit *object.Commit, fixedVersion string) (string, error) {
	logger := clog.FromContext(ctx)

	repo, err := t.getRepoAtLatest(ctx, t.moduleToGitURL[moduleName])
	if err != nil {
		return "", err
	}

	tags, err := t.tagsForCommit(ctx, repo, installedCommit)
	if err != nil {
		return "", fmt.Errorf("getting tags for commit %q: %w", installedCommit.Hash, err)
	}

	fixedVersionParsed, err := versions.NewVersion(fixedVersion)
	if err != nil {
		return "", fmt.Errorf("parsing fixed version %q: %w", fixedVersion, err)
	}

	for _, tag := range tags {
		installedVersion, err := versions.NewVersion(tag)
		if err != nil {
			logger.Debug("tag not usable", "tag", tag)
			continue
		}

		if installedVersion.GreaterThan(fixedVersionParsed) {
			return tag, nil
		}
	}

	logger.Debug("no version tag found that is later than the fixed version", "fixedVersion", fixedVersion)

	return "", nil
}

func (t *Triager) tagsForCommit(ctx context.Context, repo *git.Repository, commit *object.Commit) ([]string, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, fmt.Sprintf("tagsForCommit (%s)", commit.Hash))
	defer span.End()

	logger := clog.FromContext(ctx)

	if tags, ok := t.commitToTags[commit.Hash.String()]; ok {
		return tags, nil
	}

	logger.Debug("resolving tags for commit", "commit", commit.Hash.String())

	var tags []string

	// Iterate over all tags
	tagrefs, err := repo.Tags()
	if err != nil {
		return nil, err
	}

	err = tagrefs.ForEach(func(tagref *plumbing.Reference) error {
		var tagCommit *object.Commit

		// Resolve tag to a commit
		obj, err := repo.TagObject(tagref.Hash())
		if err == nil {
			// Annotated tag
			tagCommit, err = obj.Commit()
			if err != nil {
				return err
			}
		} else {
			// Lightweight tag
			tagCommit, err = repo.CommitObject(tagref.Hash())
			if err != nil {
				return err
			}
		}

		// Check if the tag's commit matches the given commit
		if tagCommit.Hash == commit.Hash {
			tags = append(tags, tagref.Name().Short())
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	logger.Debug("tags for commit", "commit", commit.Hash.String(), "tags", strings.Join(tags, ","))
	t.commitToTags[commit.Hash.String()] = tags

	return tags, nil
}

func (t *Triager) isAncestor(ctx context.Context, fixed, installed *object.Commit) (bool, error) {
	_, span := otel.Tracer("wolfictl").Start(ctx, fmt.Sprintf("isAncestor (%s, %s)", fixed.Hash, installed.Hash))
	defer span.End()

	hashes := commitHashes{
		fixed:     fixed.Hash.String(),
		installed: installed.Hash.String(),
	}

	if isAncestor, ok := t.isAncestorCache[hashes]; ok {
		return isAncestor, nil
	}

	isAncestor, err := fixed.IsAncestor(installed)
	if err != nil {
		return false, fmt.Errorf("checking if %q is an ancestor of %q: %w", fixed.Hash, installed.Hash, err)
	}

	t.isAncestorCache[hashes] = isAncestor

	return isAncestor, nil
}

func (t *Triager) resolveCommits(ctx context.Context, finding scan.Finding) (*commits, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, fmt.Sprintf("resolveCommits for %s in %s", finding.Vulnerability.ID, finding.Package.Name))
	defer span.End()

	logger := clog.FromContext(ctx)

	moduleName := finding.Package.Name

	// Check if we've already resolved the commits for this vulnerability and package.
	vulnID, ok := t.vulnerabilityIDToModuleNameToCommits[finding.Vulnerability.ID]
	if ok {
		commits, ok := vulnID[moduleName]
		if ok {
			return &commits, nil
		}
	}

	// Only do the online go-module-to-git-URL resolution *once* per module.
	gitURL, ok := t.moduleToGitURL[moduleName]
	if !ok {
		var err error
		gitURL, err = gomod.Repo(ctx, moduleName)
		if err != nil {
			return nil, fmt.Errorf("determining git repository for %s: %w", moduleName, err)
		}
		logger.Debug("determined git repository", "module", moduleName, "gitURL", gitURL)

		t.moduleToGitURL[moduleName] = gitURL
	}

	componentVersion := finding.Package.Version
	installedCommit, err := t.resolveModuleVersionToCommit(ctx, gitURL, componentVersion)
	if err != nil {
		return nil, fmt.Errorf("resolving installed version %q to commit: %w", componentVersion, err)
	}
	logger.Debug("resolved installed version to commit", "version", componentVersion, "commit", installedCommit.Hash.String())

	fixedVersion := finding.Vulnerability.FixedVersion

	// Adjust the tag for certain Go modules. This is a workaround for the fact that
	// some Go modules have non-standard tagging conventions. Another approach would
	// be to learn how this tag adjustment should work from the Melange YAML, but
	// this would only work for main modules and wouldn't generalize for most Go
	// module findings.
	if adjuster, ok := versionTagAdjustersByGoModule[moduleName]; ok {
		fixedVersion = adjuster(fixedVersion)
	}

	// Grype sometimes trims the "v" prefix in the fixed version, which can be fixed
	// like this:

	//nolint:gocritic // intentionally commented out
	// if !strings.HasPrefix(fixedVersion, "v") {
	// 	fixedVersion = "v" + fixedVersion
	// }

	// But we should generalize this, so we can try both forms, depending on what
	// the actual git repo ends up having.

	fixedCommit, err := t.resolveModuleVersionToCommit(ctx, gitURL, fixedVersion)
	if err != nil {
		return nil, fmt.Errorf("resolving fixed version %q to commit: %w", fixedVersion, err)
	}
	logger.Debug("resolved fixed version to commit", "vulnerabilityID", finding.Vulnerability.ID, "version", fixedVersion, "commit", fixedCommit.Hash.String())

	cs := commits{
		installed: installedCommit,
		fixed:     fixedCommit,
	}

	if _, ok := t.vulnerabilityIDToModuleNameToCommits[finding.Vulnerability.ID]; !ok {
		t.vulnerabilityIDToModuleNameToCommits[finding.Vulnerability.ID] = make(map[string]commits)
	}
	t.vulnerabilityIDToModuleNameToCommits[finding.Vulnerability.ID][moduleName] = cs

	return &cs, nil
}

// getRepoAtLatest returns a reference to a git repository, which the caller can
// assume is at the latest commit. If the repository is not in the cache, it
// will be cloned fresh and then cached. If the repository is already in the
// cache, it will be opened. If the repository is in the cache but hasn't been
// pulled since the Triager object was created, it will be pulled before being
// returned.
func (t *Triager) getRepoAtLatest(ctx context.Context, gitURL string) (*git.Repository, error) {
	logger := clog.FromContext(ctx)

	if repo, ok := t.gitURLToRepo[gitURL]; ok {
		return repo, nil
	}

	// Check if the repo cache dir exists
	_, err := os.Stat(t.repoCacheDir(gitURL))
	if err != nil {
		if os.IsNotExist(err) {
			logger.Debug("repository not in cache, cloning", "gitURL", gitURL)
			return t.cloneAndCacheRepo(ctx, gitURL)
		}

		return nil, fmt.Errorf("checking if repository %q is in cache: %w", gitURL, err)
	}

	logger.Debug("repository was found in cache but hasn't been pulled yet this session, pulling now", "gitURL", gitURL)
	return t.openAndPullRepo(ctx, gitURL)
}

func (t *Triager) cloneAndCacheRepo(ctx context.Context, gitURL string) (*git.Repository, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, fmt.Sprintf("cloning %s", gitURL))
	defer span.End()

	repo, err := git.PlainCloneContext(ctx, t.repoCacheDir(gitURL), false, &git.CloneOptions{
		URL:  gitURL,
		Tags: git.AllTags,
	})
	if err != nil {
		return nil, fmt.Errorf("cloning repository %q: %w", gitURL, err)
	}

	t.gitURLToRepo[gitURL] = repo

	return repo, nil
}

func (t *Triager) openAndPullRepo(ctx context.Context, gitURL string) (*git.Repository, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, fmt.Sprintf("pulling %s", gitURL))
	defer span.End()

	repo, err := git.PlainOpen(t.repoCacheDir(gitURL))
	if err != nil {
		return nil, fmt.Errorf("opening repository %q: %w", gitURL, err)
	}

	err = repo.FetchContext(ctx, &git.FetchOptions{
		Tags: git.AllTags,
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return nil, fmt.Errorf("fetching repository %q: %w", gitURL, err)
	}

	t.gitURLToRepo[gitURL] = repo

	return repo, nil
}

func (t Triager) repoCacheDir(gitURL string) string {
	trimmed := strings.TrimSuffix(gitURL, ".git")
	trimmed = strings.TrimPrefix(trimmed, "https://")
	trimmed = strings.TrimPrefix(trimmed, "http://")
	leafName := strings.ReplaceAll(trimmed, "/", "--")

	return filepath.Join(t.repositoriesCacheDir, leafName)
}

func eventFromConclusions(conclusions []triage.Conclusion) *v2.Event {
	eventType := triage.EventTypeFromConclusions(conclusions)

	if eventType == "" {
		// No conclusion reached
		return nil
	}

	e := &v2.Event{
		Timestamp: v2.Now(),
		Type:      eventType,
	}

	// This triager only ever finds false positives or doesn't reach a conclusion.
	if eventType == v2.EventTypeFalsePositiveDetermination {
		e.Data = v2.FalsePositiveDetermination{
			Type: v2.FPTypeVulnerableCodeVersionNotUsed,
			Note: getNoteForFalsePositive(conclusions),
		}
		return e
	}

	return nil
}

func getNoteForFalsePositive(conclusions []triage.Conclusion) string {
	// Opportunistically try to condense the explanation for the false positive.

	if explanation := condenseExplanationForIsAncestorReason(conclusions); explanation != "" {
		return explanation
	}

	if explanation := condenseExplanationForCommitHasTagOfLaterVersionReason(conclusions); explanation != "" {
		return explanation
	}

	// We'll just return the full explanation if we can't condense it, so we don't lose any information.

	sb := strings.Builder{}
	var moduleMessages []string
	for _, c := range conclusions {
		switch r := c.Reason.(type) {
		case isAncestorReason:
			m := fmt.Sprintf(
				"For path %q, module %q: the commit of the fixed version (%s) is an ancestor of installed commit (%s).",
				r.location,
				r.moduleName,
				r.fixedCommit,
				r.installedCommit,
			)
			moduleMessages = append(moduleMessages, m)

		case commitHasTagOfLaterVersionReason:
			m := fmt.Sprintf(
				"For path %q, module %q: the installed commit (%s) corresponds to a version tag (%s) that is later than the fixed version (%s).",
				r.location,
				r.moduleName,
				r.installedCommit,
				r.installedCommitTag,
				r.fixedVersion,
			)
			moduleMessages = append(moduleMessages, m)
		}
	}

	sb.WriteString(strings.Join(moduleMessages, " "))

	return sb.String()
}

func condenseExplanationForIsAncestorReason(conclusions []triage.Conclusion) string {
	if len(conclusions) == 0 {
		return ""
	}

	// This will only work if the conclusions all use the isAncestorReason type.
	var reasons []isAncestorReason
	var locations []string
	var installedCommits []string
	for _, c := range conclusions {
		r, ok := c.Reason.(isAncestorReason)
		if !ok {
			return ""
		}
		locations = append(locations, r.location)
		installedCommits = append(installedCommits, r.installedCommit)
		reasons = append(reasons, r)
	}

	slices.Sort(locations)
	locations = slices.Compact(locations)

	slices.Sort(installedCommits)
	installedCommits = slices.Compact(installedCommits)

	return fmt.Sprintf(
		"This vulnerability was matched to the module %q at the following location(s): %s. In all cases, the fixed version of the module (git commit %s) is an ancestor of the installed version commit (%s).",
		reasons[0].moduleName,
		strings.Join(locations, ", "),
		reasons[0].fixedCommit,
		strings.Join(installedCommits, ", "),
	)
}

func condenseExplanationForCommitHasTagOfLaterVersionReason(conclusions []triage.Conclusion) string {
	if len(conclusions) == 0 {
		return ""
	}

	// This will only work if the conclusions all use the commitHasTagOfLaterVersionReason type.
	var reasons []commitHasTagOfLaterVersionReason
	var locations []string
	var installedCommits []string
	for _, c := range conclusions {
		r, ok := c.Reason.(commitHasTagOfLaterVersionReason)
		if !ok {
			return ""
		}
		locations = append(locations, r.location)
		installedCommits = append(installedCommits, r.installedCommit)
		reasons = append(reasons, r)
	}

	slices.Sort(locations)
	locations = slices.Compact(locations)

	slices.Sort(installedCommits)
	installedCommits = slices.Compact(installedCommits)
	if len(installedCommits) > 1 {
		// If there are multiple installed commits, we can't condense the explanation.
		return ""
	}

	return fmt.Sprintf(
		"This vulnerability was matched to the module %q at the following location(s): %s. In all cases, the installed version of the module (git commit %s) corresponds to a version tag (%s) that is later than the fixed version (%s).",
		reasons[0].moduleName,
		strings.Join(locations, ", "),
		reasons[0].installedCommit,
		reasons[0].installedCommitTag,
		reasons[0].fixedVersion,
	)
}

func (t *Triager) resolveModuleVersionToCommit(ctx context.Context, gitURL, version string) (*object.Commit, error) {
	repo, err := t.getRepoAtLatest(ctx, gitURL)
	if err != nil {
		return nil, fmt.Errorf("getting repository at latest commit: %w", err)
	}

	if commit, ok := t.repoVersionToCommit[gitURL][version]; ok {
		return commit, nil
	}

	if gomod.IsPseudoVersion(version) {
		// Extract the commit hash from the pseudo-version
		commitHash := strings.Split(version, "-")[2]

		// Resolve the partial commit hash to a full commit hash
		fullHash, err := repo.ResolveRevision(plumbing.Revision(commitHash))
		if err != nil {
			return nil, fmt.Errorf("resolving partial commit hash %q: %w", commitHash, err)
		}

		// Get the commit object for the commit hash
		commit, err := repo.CommitObject(*fullHash)
		if err != nil {
			return nil, fmt.Errorf("getting commit object for hash %q: %w", commitHash, err)
		}

		t.repoVersionToCommit[gitURL] = map[string]*object.Commit{
			version: commit,
		}

		return commit, nil
	}

	// Assume the version is a Git tag
	tagRef, err := repo.Tag(version)
	if err != nil {
		return nil, fmt.Errorf("getting tag %q: %w", version, err)
	}

	// Try to get the tag object for the tag
	tag, err := repo.TagObject(tagRef.Hash())
	if err != nil {
		// If there's an error, assume it's a lightweight tag and get the commit object directly
		commit, err := repo.CommitObject(tagRef.Hash())
		if err != nil {
			return nil, fmt.Errorf("getting commit object for lightweight tag %q: %w", version, err)
		}

		t.repoVersionToCommit[gitURL] = map[string]*object.Commit{
			version: commit,
		}

		return commit, nil
	}

	// If it's an annotated tag, get the commit object for the tag
	commit, err := repo.CommitObject(tag.Target)
	if err != nil {
		return nil, fmt.Errorf("getting commit object for annotated tag %q: %w", version, err)
	}

	t.repoVersionToCommit[gitURL] = map[string]*object.Commit{
		version: commit,
	}

	return commit, nil
}

var versionTagAdjustersByGoModule = map[string]func(string) string{
	"k8s.io/ingress-nginx": func(v string) string {
		return fmt.Sprintf("controller-v%s", v)
	},
}
