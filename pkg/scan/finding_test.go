package scan

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMapMatchToFinding(t *testing.T) {
	tests := []struct {
		name  string
		match match.Match
		want  *Finding
	}{
		{
			name: "basic vulnerability with metadata",
			match: match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-1234",
						Namespace: "nvd:cpe",
					},
					PackageName: "test-package",
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateFixed,
						Versions: []string{"1.0.1"},
					},
					RelatedVulnerabilities: []vulnerability.Reference{},
					Metadata: &vulnerability.Metadata{
						ID:       "CVE-2023-1234",
						Severity: "high",
					},
				},
				Package: pkg.Package{
					ID:      pkg.ID("pkg-123"),
					Name:    "test-package",
					Version: "1.0.0",
					Type:    syftPkg.ApkPkg,
					PURL:    "pkg:apk/wolfi/test-package@1.0.0",
					Locations: file.NewLocationSet(
						file.NewLocation("/usr/bin/test"),
					),
				},
			},
			want: &Finding{
				Package: Package{
					ID:       "pkg-123",
					Name:     "test-package",
					Version:  "1.0.0",
					Type:     "apk",
					Location: "/usr/bin/test",
					PURL:     "pkg:apk/wolfi/test-package@1.0.0",
				},
				Vulnerability: Vulnerability{
					ID:           "CVE-2023-1234",
					Severity:     "high",
					Aliases:      []string{},
					FixedVersion: "1.0.1",
				},
			},
		},
		{
			name: "vulnerability with related vulnerabilities (aliases)",
			match: match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-1234",
						Namespace: "nvd:cpe",
					},
					PackageName: "test-package",
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateFixed,
						Versions: []string{"1.0.1"},
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							ID:        "GHSA-xxxx-yyyy-zzzz",
							Namespace: "github:language:go",
						},
						{
							ID:        "CVE-2023-5678",
							Namespace: "nvd:cpe",
						},
					},
					Metadata: &vulnerability.Metadata{
						ID:       "CVE-2023-1234",
						Severity: "high",
					},
				},
				Package: pkg.Package{
					ID:      pkg.ID("pkg-123"),
					Name:    "test-package",
					Version: "1.0.0",
					Type:    syftPkg.ApkPkg,
					PURL:    "pkg:apk/wolfi/test-package@1.0.0",
					Locations: file.NewLocationSet(
						file.NewLocation("/usr/bin/test"),
					),
				},
			},
			want: &Finding{
				Package: Package{
					ID:       "pkg-123",
					Name:     "test-package",
					Version:  "1.0.0",
					Type:     "apk",
					Location: "/usr/bin/test",
					PURL:     "pkg:apk/wolfi/test-package@1.0.0",
				},
				Vulnerability: Vulnerability{
					ID:           "CVE-2023-1234",
					Severity:     "high",
					Aliases:      []string{"GHSA-xxxx-yyyy-zzzz", "CVE-2023-5678"},
					FixedVersion: "1.0.1",
				},
			},
		},
		{
			name: "vulnerability with self-referencing related vulnerability (should be filtered)",
			match: match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-1234",
						Namespace: "nvd:cpe",
					},
					PackageName: "test-package",
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateFixed,
						Versions: []string{"1.0.1"},
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							ID:        "CVE-2023-1234", // Same as main vulnerability
							Namespace: "nvd:cpe",
						},
						{
							ID:        "GHSA-xxxx-yyyy-zzzz",
							Namespace: "github:language:go",
						},
					},
					Metadata: &vulnerability.Metadata{
						ID:       "CVE-2023-1234",
						Severity: "high",
					},
				},
				Package: pkg.Package{
					ID:      pkg.ID("pkg-123"),
					Name:    "test-package",
					Version: "1.0.0",
					Type:    syftPkg.ApkPkg,
					PURL:    "pkg:apk/wolfi/test-package@1.0.0",
					Locations: file.NewLocationSet(
						file.NewLocation("/usr/bin/test"),
					),
				},
			},
			want: &Finding{
				Package: Package{
					ID:       "pkg-123",
					Name:     "test-package",
					Version:  "1.0.0",
					Type:     "apk",
					Location: "/usr/bin/test",
					PURL:     "pkg:apk/wolfi/test-package@1.0.0",
				},
				Vulnerability: Vulnerability{
					ID:           "CVE-2023-1234",
					Severity:     "high",
					Aliases:      []string{"GHSA-xxxx-yyyy-zzzz"}, // CVE-2023-1234 filtered out
					FixedVersion: "1.0.1",
				},
			},
		},
		{
			name: "vulnerability with no fix",
			match: match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-1234",
						Namespace: "nvd:cpe",
					},
					PackageName: "test-package",
					Fix: vulnerability.Fix{
						State: vulnerability.FixStateUnknown,
					},
					RelatedVulnerabilities: []vulnerability.Reference{},
					Metadata: &vulnerability.Metadata{
						ID:       "CVE-2023-1234",
						Severity: "critical",
					},
				},
				Package: pkg.Package{
					ID:      pkg.ID("pkg-123"),
					Name:    "test-package",
					Version: "1.0.0",
					Type:    syftPkg.ApkPkg,
					PURL:    "pkg:apk/wolfi/test-package@1.0.0",
					Locations: file.NewLocationSet(
						file.NewLocation("/usr/bin/test"),
					),
				},
			},
			want: &Finding{
				Package: Package{
					ID:       "pkg-123",
					Name:     "test-package",
					Version:  "1.0.0",
					Type:     "apk",
					Location: "/usr/bin/test",
					PURL:     "pkg:apk/wolfi/test-package@1.0.0",
				},
				Vulnerability: Vulnerability{
					ID:           "CVE-2023-1234",
					Severity:     "critical",
					Aliases:      []string{},
					FixedVersion: "", // No fix available
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapMatchToFinding(tt.match)
			if got == nil {
				t.Fatal("mapMatchToFinding() returned nil")
			}

			// Compare the results
			if got.Package.ID != tt.want.Package.ID {
				t.Errorf("Package.ID = %v, want %v", got.Package.ID, tt.want.Package.ID)
			}
			if got.Package.Name != tt.want.Package.Name {
				t.Errorf("Package.Name = %v, want %v", got.Package.Name, tt.want.Package.Name)
			}
			if got.Package.Version != tt.want.Package.Version {
				t.Errorf("Package.Version = %v, want %v", got.Package.Version, tt.want.Package.Version)
			}
			if got.Package.Type != tt.want.Package.Type {
				t.Errorf("Package.Type = %v, want %v", got.Package.Type, tt.want.Package.Type)
			}
			if got.Package.PURL != tt.want.Package.PURL {
				t.Errorf("Package.PURL = %v, want %v", got.Package.PURL, tt.want.Package.PURL)
			}

			if got.Vulnerability.ID != tt.want.Vulnerability.ID {
				t.Errorf("Vulnerability.ID = %v, want %v", got.Vulnerability.ID, tt.want.Vulnerability.ID)
			}
			if got.Vulnerability.Severity != tt.want.Vulnerability.Severity {
				t.Errorf("Vulnerability.Severity = %v, want %v", got.Vulnerability.Severity, tt.want.Vulnerability.Severity)
			}
			if got.Vulnerability.FixedVersion != tt.want.Vulnerability.FixedVersion {
				t.Errorf("Vulnerability.FixedVersion = %v, want %v", got.Vulnerability.FixedVersion, tt.want.Vulnerability.FixedVersion)
			}

			// Compare aliases
			if len(got.Vulnerability.Aliases) != len(tt.want.Vulnerability.Aliases) {
				t.Errorf("Vulnerability.Aliases length = %v, want %v", len(got.Vulnerability.Aliases), len(tt.want.Vulnerability.Aliases))
			} else {
				for i := range got.Vulnerability.Aliases {
					if got.Vulnerability.Aliases[i] != tt.want.Vulnerability.Aliases[i] {
						t.Errorf("Vulnerability.Aliases[%d] = %v, want %v", i, got.Vulnerability.Aliases[i], tt.want.Vulnerability.Aliases[i])
					}
				}
			}
		})
	}
}
