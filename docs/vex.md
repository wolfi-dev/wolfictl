# VEX Metadata From Wolfi Packages 

One of the key design features of the Wolfi toolchain is its rich generation
of supply chain metadata as part of its build processes. All Wolfi packages
get a software bill of materials (SBOM) and to complement it, Vulnerability
Exploitability Exchange (VEX) metadata can be generated to help with false
positives in security scans exacerbated by the extreme transparency offered
by all the available data.

If you are unfamiliar with VEX, you can think of it as a negative security
advisory. A document where software authors inform users that a vulnerability
does not affect a program. For more information check out Chainguard's
[introductory VEX blog post](https://www.chainguard.dev/unchained/understanding-the-promise-of-vex).

## Patching Wolfi

The Wolfi project automatically monitors feeds to detect when new versions of
software packaged in the operating system become available. When a new version
is released or a vulnerability is found, its corresponding Wolfi package gets
patched. If the patch or update was released to address a new vulnerability 
disclosure, a Wolfi Security Advisory is issued. For more information on 
the patching process or (even better!) if you want to contribute check out the
[How To Patch CVEs document](https://github.com/wolfi-dev/os/blob/main/HOW_TO_PATCH_CVES.md).

Security advisories contain the patch history of the package. The data in the
advisories lets users know when the project became aware of a vulnerability, if
it affects the package, which versions are impacted, and how quickly it was
handled by the Wolfi team after disclosure. Sometimes security scanners will
miss these patches and falsely report the package as vulnerable. Here is where
VEX can help.

## How Wolfi VEX Metadata is Generated

By translating the Wolfi advisories into VEX metadata, the project can piece
together the full history of exploitability knowledge for each of its packages
in a machine-readable way. When those packages are used developers using Wolfi
can know exactly what is inside their images with the SBOM but now, using VEX,
they can also know if those packages are vulnerable to be be exploited.

Wolfi uses OpenVEX to compose its VEX documents. For more information see
the [OpenVEX](https://openvex.dev) project and specification.

### VEX From OS Packages

VEX metadata can be generated for any Wolfi package that contains at least one
security advisory. Security advisories are recorded in the package’s build
configuration file, and all package configuration files are maintained in the
[Wolfi OS](https://github.com/wolfi-dev/os) repository.

For example, to generate a VEX document about the Wolfi
[git package](https://github.com/wolfi-dev/os/blob/main/git.yaml) invoke
`wolfictl` as follows:

```console
wolfictl vex package git.yaml
```

Note: As with other `wolfictl` subcommands, the program assumes it is being run
at the top of the [wolfi-dev/os](https://github.com/wolfi-dev/os) repository.

The document we get captures the history of fixes done to the git package:

```json
{
  "@context": "https://openvex.dev/ns",
  "@id": "vex-75479ed534c34759b8cc4f0ecea9beb515c144c3e99d4b85dfc9f79cb39c5138",
  "author": "Unknown Author",
  "role": "Document Creator",
  "timestamp": "2023-01-23T19:46:15.95891029-06:00",
  "version": "1",
  "statements": [
    {
      "vulnerability": "CVE-2022-39253",
      "timestamp": "2022-10-19T21:10:17Z",
      "products": [
        "pkg:apk/wolfi/git@2.39.0-r1",
        "pkg:apk/wolfi/git-daemon@2.39.0-r1",
        "pkg:apk/wolfi/git-email@2.39.0-r1",
        "pkg:apk/wolfi/git-p4@2.39.0-r1"
      ],
      "status": "fixed"
    },
    {
      "vulnerability": "CVE-2022-39260",
      "timestamp": "2022-10-19T21:10:17Z",
      "products": [
        "pkg:apk/wolfi/git@2.39.0-r1",
        "pkg:apk/wolfi/git-daemon@2.39.0-r1",
        "pkg:apk/wolfi/git-email@2.39.0-r1",
        "pkg:apk/wolfi/git-p4@2.39.0-r1"
      ],
      "status": "fixed"
    }
  ]
}
```

Single package documents can be used downstream by other “products” (in the VEX
lingo) that are composed, at least in part, with Wolfi packages. The most
obvious example is when generating a VEX document from container images.

### VEXing Container Images

The real value of the VEX data flowing through the Wolfi ecosystem is realized
when it informs of the exploitability status in container images assembled from
the OS packages. By reading an image SBOM, `wolfictl` can look up the known data
about each OS package and compose a VEX document that talks about that
particular image as a product.

To generate a VEX document about a Wolfi-based image, invoke `wolfictl vex sbom`
and specify the image SBOM:

```
wolfictl vex sbom file.spdx.json
```

If the image has an SBOM already attached to it, you can simply pass the image
reference to `wolfictl`:

```
wolfictl vex sbom registry/repository/image:latest
```

`wolfictl vex sbom` was designed to vex container images, but any
[SPDX](https://spdx.dev/) SBOM that lists Wolfi packages should be able to get
its companion VEX document as long as the packages are properly identified with
a [Package URL](https://github.com/package-url/purl-spec) (purl).

`wolfictl` can retrieve SBOMs that have been attached using
[Sigstore](https://sigstore.dev/)'s
[cosign SBOM spec](https://github.com/sigstore/cosign/blob/main/specs/SBOM_SPEC.md).

## A Real Life Example: Understanding a VEX Document

Let's take a look at an example. We will enerate a VEX Document using the SBOM
of [the Chainguard `static` base image](https://github.com/chainguard-images/images/tree/main/images/static)
(the example uses the digest of the amd64 variant at the time of writing).

First, let’s look at what is inside the SBOM. The SBOM is attached to the image
so we can retrieve it using [sigstore’s `cosign`](https://github.com/sigstore/cosign/)
and visualize it using
[`bom` the SBOM tool from Kubernetes](http://github.com/kubernetes-sigs/bom):


```console
cosign download sbom \
  cgr.dev/chainguard/static@sha256:c1c818750c4b36a994cd635df62a417123912e251ac53c9866e5794f2de3d073 | \
  bom document outline --purl --depth=3 -

 📂 SPDX Document sbom-sha256:ee651549bcb02546f53933a6e3e6c9dab7770e29097d5688f06547ddf0dc2336
  │ 
  │ 📦 DESCRIBES 1 Packages
  │ 
  ├ pkg:oci/static@sha256:c1c818750c4b36a994cd635df62a417123912e251ac53c9866e5794f2de3d073?arch=amd64&mediatype=application%2Fvnd.oci.image.manifest.v1+json&os=linux
  │  │ 🔗 2 Relationships
  │  ├ CONTAINS PACKAGE pkg:oci/static@sha256:ee651549bcb02546f53933a6e3e6c9dab7770e29097d5688f06547ddf0dc2336?arch=amd64&mediatype=application%2Fvnd.oci.image.layer.v1.tar+gzip&os=linux
  │  │  │ 🔗 4 Relationships
  │  │  ├ CONTAINS PACKAGE pkg:apk/wolfi/ca-certificates-bundle@20220614-r2?arch=x86_64
  │  │  ├ CONTAINS PACKAGE pkg:apk/wolfi/tzdata@2022g-r0?arch=x86_64 
  │  │  │  └ 🔗 1199 Relationships
  │  │  │ 
  │  │  ├ CONTAINS PACKAGE pkg:apk/wolfi/glibc-locale-posix@2.36-r4?arch=x86_64
  │  │  │  └ 🔗 12 Relationships
  │  │  │ 
  │  │  └ CONTAINS PACKAGE pkg:apk/wolfi/wolfi-baselayout@20221118-r0?arch=x86_64
  │  │ 
  │  └ GENERATED_FROM PACKAGE pkg:github/chainguard-images/images@bb50b31546d9ae34cbfb227f10024c757a7b1e22
  │ 
  └ 📄 DESCRIBES 0 Files

```

From the text diagram above, we know that the image contains four Wolfi
packages: 
[`ca-certificates-bundle`](https://github.com/wolfi-dev/os/blob/main/ca-certificates.yaml),
[`glibc-locale-posix`](https://github.com/wolfi-dev/os/blob/2925e13da033d01c2494ebda57a12c25b51dd13f/glibc.yaml#L415),
[`tzdata`](https://github.com/wolfi-dev/os/blob/main/tzdata.yaml),
and
[`wolfi-baselayout`](https://github.com/wolfi-dev/os/blob/main/wolfi-baselayout.yaml).

If we generate a VEX document from the image SBOM, `wolfictl` will capture all
the history of impact analysis from the Wolfi Security Advisories into the
VEX statements:

```console
wolfictl vex sbom cgr.dev/chainguard/static@sha256:c1c818750c4b36a994cd635df62a417123912e251ac53c9866e5794f2de3d073
```

```json
{
  "@context": "https://openvex.dev/ns",
  "@id": "merged-vex-81361bfc0d69a7741cb9d3b12809f8b7678404701f19650c4c680477155de373",
  "author": "Unknown Author",
  "role": "Document Creator",
  "timestamp": "2023-01-23T17:59:04.273286693-06:00",
  "version": "1",
  "statements": [
    {
      "vulnerability": "CVE-2022-39046",
      "timestamp": "2023-01-23T17:59:04.273077241-06:00",
      "products": [
        "pkg:oci/static@sha256:c1c818750c4b36a994cd635df62a417123912e251ac53c9866e5794f2de3d073?arch=amd64&mediaType=application%2Fvnd.oci.image.manifest.v1%2Bjson&os=linux"
      ],
      "subcomponents": [
        "pkg:apk/wolfi/glibc-locale-posix@2.36-r4"
      ],
      "status": "fixed"
    }
  ]
}

```

Exploring the VEX document, we'll notice that `wolfictl` generated a document
containing a single VEX statement. The statement combines the required VEX
fields from completeness: a vulnerability, a product, and an impact status:

- It talks about the image, the “product” entry in the statement, identified by the image purl.
- It pairs it with [CVE-2022-39046](https://nvd.nist.gov/vuln/detail/CVE-2022-39046),
the identifier is in the vulnerability field.
- And, finally, it also conveys an
[impact status](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-labels):
“fixed”.

The document also specifies the subcomponent where the vulnerability originated:
the Wolfi package identified by the purl `pkg:apk/wolfi/glibc-locale-posix@2.36-r4`.

When evaluating the `static` image, a scanner can read the VEX metadata in the
document and turn off any false positives it finds by relying on data originated
at the source: the Wolfi maintainers themselves. While scanners are preparing to
support VEX filtering natively, filtering, 
[OpenVEX's `vexctl`](https://github.com/openvex/vexctl) can be used to filter out
false positives from scanner results.


