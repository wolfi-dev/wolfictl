package sbom

import (
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
)

// generateWfnAttributesForAPK generates a CPE for an APK package. If the package is
// not recognized, this function will return nil.
func generateWfnAttributesForAPK(p pkgInfo) *wfn.Attributes {
	name := p.Origin
	version := trimAPKVersionEpoch(p.PkgVer)

	// Give first priority to our maintained list of CPE mappings by APK package
	// name.

	attr := wfn.Attributes{
		Part:    "a",
		Version: version,
	}

	if w, ok := pkgNameToWfnAttributes[name]; ok {
		attr.Vendor = w.Vendor
		attr.Product = w.Product

		return &attr
	}

	// TODO: This is a workaround for Syft not coming up with this CPE for OpenJDK
	// 	packages. Some thought would be needed on the "right" way to implement this
	// 	upstream, but it's more obvious how we can address this in wolfictl for our
	// 	purposes.
	//
	//  Potentially related: https://github.com/anchore/syft/issues/2422
	if strings.HasPrefix(name, "openjdk-") {
		attr.Vendor = "oracle"
		attr.Product = "jdk"

		return &attr
	}

	if strings.HasPrefix(name, "corretto-") {
		attr.Vendor = "oracle"
		attr.Product = "jdk"

		return &attr
	}

	if strings.HasPrefix(name, "dotnet-") {
		attr.Vendor = "microsoft"
		attr.Product = ".net"

		return &attr
	}

	if strings.HasPrefix(name, "gitlab-") {
		attr.Vendor = "gitlab"
		attr.Product = "gitlab"
		attr.SWEdition = "community"

		return &attr
	}

	return nil
}

func trimAPKVersionEpoch(version string) string {
	// An epoch is denoted with a suffix of "-rN", where N is a number. We want to
	// remove this suffix from the version.
	if idx := strings.LastIndex(version, "-r"); idx != -1 {
		return version[:idx]
	}

	return version
}

// pkgNameToWfnAttributes is a set of known mappings from package name to WFN
// attributes. This is used to generate CPEs for APK packages.
//
// Please keep this list sorted alphabetically!
var pkgNameToWfnAttributes = map[string]wfn.Attributes{
	"bind": {
		Vendor:  "isc",
		Product: "bind",
	},
	"binutils": {
		Vendor:  "gnu",
		Product: "binutils",
	},
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
	"gcc": {
		Vendor:  "gnu",
		Product: "gcc",
	},
	"git": {
		Vendor:  "git-scm",
		Product: "git",
	},
	"jenkins": {
		Vendor:  "jenkins",
		Product: "jenkins",
	},
	"libtasn1": {
		Vendor:  "gnu",
		Product: "libtasn1",
	},
	"memcached": {
		Vendor:  "memcached",
		Product: "memcached",
	},
	"ncurses": {
		Vendor:  "gnu",
		Product: "ncurses",
	},
	"openjdk": {
		Vendor:  "oracle",
		Product: "openjdk",
	},
	"openssl-provider-fips": {
		Vendor:  "openssl",
		Product: "openssl",
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
