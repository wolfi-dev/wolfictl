package deps

import (
	"testing"

	"chainguard.dev/melange/pkg/config"
)

func TestFixedDepsList(t *testing.T) {
	testcases := []struct {
		name                 string
		cfg                  *config.Configuration
		wantDeps             string
		wantReplaces         string
		removeGoBumpPipeline bool
	}{{
		name:     "remove the old crypto dependency",
		wantDeps: "github.com/pkg/errors@v10.10.10",
		cfg: &config.Configuration{
			Pipeline: []config.Pipeline{
				{
					Uses: "git-checkout",
					With: map[string]string{
						"repository":      "https://gitlab.com/gitlab-org/gitlab-pages.git",
						"tag":             "v16.7.3",
						"expected-commit": "135ee38d50c2973c4a6c559b19b417af29465648",
					},
				},
				{
					Uses: "go/bump",
					With: map[string]string{
						"deps": "golang.org/x/crypto@v0.14.0 github.com/pkg/errors@v10.10.10",
					},
				},
			},
			Subpackages: []config.Subpackage{{
				Name: "cats",
				Pipeline: []config.Pipeline{{
					Runs: "cats are angry",
				}},
			}},
		},
	}, {
		name:     "cleanup deps",
		wantDeps: "",
		cfg: &config.Configuration{
			Pipeline: []config.Pipeline{
				{
					Uses: "git-checkout",
					With: map[string]string{
						"repository":      "https://gitlab.com/gitlab-org/gitlab-pages.git",
						"tag":             "v16.7.3",
						"expected-commit": "135ee38d50c2973c4a6c559b19b417af29465648",
					},
				},
				{
					Uses: "go/bump",
					With: map[string]string{
						"deps":     "golang.org/x/crypto@v0.14.0",
						"replaces": "github.com/namsral/flag=github.com/namsral/flag@v100.100.100",
					},
				},
			},
			Subpackages: []config.Subpackage{{
				Name: "cats",
				Pipeline: []config.Pipeline{{
					Runs: "cats are angry",
				}},
			}},
		},
	}, {
		name:         "cleanup replaces",
		wantDeps:     "github.com/pkg/errors@v10.10.10",
		wantReplaces: "github.com/namsral/flag=github.com/namsral/flag@v100.100.100",
		cfg: &config.Configuration{
			Pipeline: []config.Pipeline{
				{
					Uses: "git-checkout",
					With: map[string]string{
						"repository":      "https://gitlab.com/gitlab-org/gitlab-pages.git",
						"tag":             "v16.7.3",
						"expected-commit": "135ee38d50c2973c4a6c559b19b417af29465648",
					},
				},
				{
					Uses: "go/bump",
					With: map[string]string{
						"deps":     "github.com/pkg/errors@v10.10.10",
						"replaces": "golang.org/x/crypto=golang.org/x/crypto@v0.14.0 github.com/namsral/flag=github.com/namsral/flag@v100.100.100",
					},
				},
			},
			Subpackages: []config.Subpackage{{
				Name: "cats",
				Pipeline: []config.Pipeline{{
					Runs: "cats are angry",
				}},
			}},
		},
	}}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := CleanupGoBumpDeps(tc.cfg, false, map[string]string{})
			if err != nil {
				t.Fatalf("failed to cleanup go bump deps: %v", err)
			}
			if tc.cfg.Pipeline[1].With["deps"] != tc.wantDeps {
				t.Errorf("expect '%s', got '%s'", tc.wantDeps, tc.cfg.Pipeline[1].With["deps"])
			}
			if tc.wantReplaces != "" {
				if tc.cfg.Pipeline[1].With["replaces"] != tc.wantReplaces {
					t.Errorf("expect replaces '%s', got '%s'", tc.wantReplaces, tc.cfg.Pipeline[1].With["replaces"])
				}
			}
		})
	}
}

func TestRemovalGoBumpPipeline(t *testing.T) {
	testcases := []struct {
		name                 string
		cfg                  *config.Configuration
		removeGoBumpPipeline bool
	}{{
		name:                 "cleanup gobump, empty deps",
		removeGoBumpPipeline: true,
		cfg: &config.Configuration{
			Pipeline: []config.Pipeline{
				{
					Uses: "git-checkout",
					With: map[string]string{
						"repository":      "https://gitlab.com/gitlab-org/gitlab-pages.git",
						"tag":             "v16.7.3",
						"expected-commit": "135ee38d50c2973c4a6c559b19b417af29465648",
					},
				},
				{
					Uses: "go/bump",
					With: map[string]string{
						"deps": "golang.org/x/crypto@v0.14.0",
					},
				},
			},
			Subpackages: []config.Subpackage{{
				Name: "cats",
				Pipeline: []config.Pipeline{{
					Runs: "cats are angry",
				}},
			}},
		},
	}, {
		name:                 "cleanup gobump, empty replaces",
		removeGoBumpPipeline: true,
		cfg: &config.Configuration{
			Pipeline: []config.Pipeline{
				{
					Uses: "git-checkout",
					With: map[string]string{
						"repository":      "https://gitlab.com/gitlab-org/gitlab-pages.git",
						"tag":             "v16.7.3",
						"expected-commit": "135ee38d50c2973c4a6c559b19b417af29465648",
					},
				},
				{
					Uses: "go/bump",
					With: map[string]string{
						"replaces": "golang.org/x/crypto=golang.org/x/crypto@v0.14.0",
					},
				},
			},
			Subpackages: []config.Subpackage{{
				Name: "cats",
				Pipeline: []config.Pipeline{{
					Runs: "cats are angry",
				}},
			}},
		},
	}}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			length := len(tc.cfg.Pipeline)
			mutatations := map[string]string{}
			err := CleanupGoBumpDeps(tc.cfg, false, mutatations)
			if err != nil {
				t.Fatalf("failed to cleanup go bump deps: %v", err)
			}
			if tc.removeGoBumpPipeline {
				if len(tc.cfg.Pipeline) != (length - 1) {
					t.Errorf("expected the configuration to remove the go/bump pipeline: %v", tc.cfg)
				}
			}
		})
	}
}
