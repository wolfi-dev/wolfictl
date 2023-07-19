package update

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wolfi-dev/wolfictl/pkg/melange"

	"chainguard.dev/melange/pkg/build"

	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-billy/v5/util"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"gopkg.in/yaml.v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// a bit more than a typical unit test but is useful to test a git branch with melange bump
func TestMonitorService_updatePackagesGitRepository(t *testing.T) {
	dir := t.TempDir()

	data, err := os.ReadFile(filepath.Join("testdata", "cheese-1.5.10.tar.gz"))
	assert.NoError(t, err)

	// create a test server for melange bump to fetch the tarball and generate SHA
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		assert.Equal(t, req.URL.String(), "/wine/cheese/cheese-1.5.10.tar.gz")

		// Send response to be tested
		_, err = rw.Write(data)
		assert.NoError(t, err)
	}))

	r := setupTestWolfiRepo(t, dir, server.URL)

	o := Options{
		DryRun:        true,
		Logger:        log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
		DefaultBranch: "master",
	}

	o.PackageConfigs, err = melange.ReadAllPackagesFromRepo(filepath.Join(dir, "melange"))
	assert.NoError(t, err)

	// fake a new version available
	newVersion := map[string]NewVersionResults{"cheese": {Version: "1.5.10"}}
	errorMessages := make(map[string]string)
	err = o.updatePackagesGitRepository(r, newVersion)
	assert.NoError(t, err)
	assert.Empty(t, errorMessages)

	// assert the results
	rsData, err := os.ReadFile(filepath.Join(dir, "melange", "cheese.yaml"))
	assert.NoError(t, err)

	rsMelangeConfig := &build.Configuration{}
	err = yaml.Unmarshal(rsData, rsMelangeConfig)
	assert.NoError(t, err)

	assert.Equal(t, "1.5.10", rsMelangeConfig.Package.Version)
	assert.Equal(t, "cc2c52929ace57623ff517408a577e783e10042655963b2c8f0633e109337d7a", rsMelangeConfig.Pipeline[0].With["expected-sha256"])
}

func setupTestWolfiRepo(t *testing.T, dir, testURL string) *git.Repository {
	fs := osfs.New(dir)
	data, err := os.ReadFile(filepath.Join("testdata", "cheese.yaml"))
	assert.NoError(t, err)

	// replace the URL melange bump uses to fetch the tarball from
	melangConfig := strings.Replace(string(data), "REPLACE_ME", testURL, 1)

	storage := filesystem.NewStorage(fs, cache.NewObjectLRUDefault())
	wt, err := fs.Chroot("melange")
	assert.NoError(t, err)

	r, err := git.Init(storage, wt)
	assert.NoError(t, err)

	w, err := r.Worktree()
	assert.NoError(t, err)

	err = util.WriteFile(w.Filesystem, "cheese.yaml", []byte(melangConfig), 0o644)
	assert.NoError(t, err)

	_, err = w.Add("cheese.yaml")
	assert.NoError(t, err)

	_, err = w.Commit("initial test checkin", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "John Doe",
			Email: "john@doe.org",
			When:  time.Now(),
		},
	})
	assert.NoError(t, err)

	return r
}

// a bit more than a typical unit test but is useful to test a git branch with melange bump
func TestUpdate_updateMakefile(t *testing.T) {
	tempDir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("testdata", "Makefile"))
	assert.NoError(t, err)

	// make the temp test dir a git repo
	fs := osfs.New(tempDir)
	storage := filesystem.NewStorage(fs, cache.NewObjectLRUDefault())
	wt, err := fs.Chroot("melange")
	require.NoError(t, err)
	r, err := git.Init(storage, wt)
	assert.NoError(t, err)
	w, err := r.Worktree()
	require.NoError(t, err)

	// copy test file into temp git repo
	err = util.WriteFile(w.Filesystem, "Makefile", data, 0o644)
	assert.NoError(t, err)

	o := Options{
		Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
	}
	err = o.updateMakefile(filepath.Join(tempDir, "melange"), "zlib", "1.3.0", w)
	assert.NoError(t, err)

	// assert the Makefile contains the correct changes
	resultData, err := os.ReadFile(filepath.Join(tempDir, "melange", "Makefile"))
	assert.NoError(t, err)
	assert.Contains(t, string(resultData), "build-package,zlib,1.3.0-r0)")
}

func Test_extractVersionFromTitle(t *testing.T) {
	tests := []struct {
		title       string
		wantPackage string
		wantVersion string
		wantErr     assert.ErrorAssertionFunc
	}{
		{title: "foo/1.11.0 package update", wantPackage: "foo", wantVersion: "1.11.0", wantErr: assert.NoError},
		{title: "foo/1.11 package update", wantPackage: "foo", wantVersion: "1.11", wantErr: assert.NoError},
		{title: "foo/1 package update", wantPackage: "foo", wantVersion: "1", wantErr: assert.NoError},
		{title: "no package update", wantPackage: "", wantVersion: "", wantErr: assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			got1, got2, err := extractPackageVersionFromTitle(tt.title)
			if !tt.wantErr(t, err, fmt.Sprintf("extractVersionFromTitle(%v)", tt.title)) {
				return
			}
			assert.Equalf(t, tt.wantPackage, got1, "extractVersionFromTitle(%v)", tt.title)
			assert.Equalf(t, tt.wantVersion, got2, "extractVersionFromTitle(%v)", tt.title)
		})
	}
}

func TestOptions_getPackagesToUpdate(t *testing.T) {
	logger := log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix)
	melangeConfigs := map[string]*melange.Packages{
		"foo": {
			Config: build.Configuration{
				Package: build.Package{
					Name:    "foo",
					Version: "1.0.0",
				},
				Pipeline: []build.Pipeline{
					{
						Uses: "git-checkout",
						With: map[string]string{
							"expected-commit": "1234567890",
						},
					},
				},
			},
		},
	}

	type args struct {
		latestVersions map[string]NewVersionResults
	}
	tests := []struct {
		name string
		args args
		want map[string]NewVersionResults
	}{
		{
			name: "no packages to update",
			args: args{
				latestVersions: map[string]NewVersionResults{
					"foo": {Version: "1.0.0", Commit: "1234567890", BumpEpoch: false}, // same version and commit
				},
			},
			want: map[string]NewVersionResults{},
		},
		{
			name: "update with new version",
			args: args{
				latestVersions: map[string]NewVersionResults{
					"foo": {Version: "2.0.0"},
				},
			},
			want: map[string]NewVersionResults{"foo": {Version: "2.0.0", BumpEpoch: false}}, // new version
		},
		{
			// if versions match but the commit doesn't then we need to update the commit
			// this can occur when an upstream project recreated a tag with a new commit
			name: "update as we have incorrect expected commit",
			args: args{
				latestVersions: map[string]NewVersionResults{
					"foo": {Version: "1.0.0", Commit: "4444444444"},
				},
			},
			want: map[string]NewVersionResults{"foo": {Version: "1.0.0", Commit: "4444444444", BumpEpoch: true}}, // new commit
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{
				PackageConfigs: melangeConfigs,
				Logger:         logger,
			}
			got, err := o.getPackagesToUpdate(tt.args.latestVersions)
			assert.NoError(t, err)
			assert.Equalf(t, tt.want, got, "getPackagesToUpdate(%v)", tt.args.latestVersions)
		})
	}
}
