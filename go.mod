module github.com/wolfi-dev/wolfictl

go 1.20

replace gitlab.alpinelinux.org/alpine/go => gitlab.alpinelinux.org/jdolitsky/go v0.5.2-0.20230428222852-3db8d023b49b

replace k8s.io/client-go => k8s.io/client-go v0.25.3

replace chainguard.dev/melange => github.com/rawlingsj/melange v0.0.0-20230610150205-f7bf4dce44e3

require (
	chainguard.dev/apko v0.8.1-0.20230605181514-e6a8234eef62
	chainguard.dev/melange v0.3.1-0.20230502151024-40098bfea030
	cloud.google.com/go/storage v1.30.1
	github.com/chainguard-dev/go-apk v0.0.0-20230605180416-2829525a7136
	github.com/chainguard-dev/kontext v0.1.0
	github.com/chainguard-dev/yam v0.0.0-20230515182324-679f6de74032
	github.com/charmbracelet/bubbles v0.15.0
	github.com/charmbracelet/bubbletea v0.23.2
	github.com/charmbracelet/lipgloss v0.7.1
	github.com/cpuguy83/go-md2man v1.0.10
	github.com/dominikbraun/graph v0.22.2-0.20230606093412-daffba1d8554
	github.com/dprotaso/go-yit v0.0.0-20220510233725-9ba8df137936
	github.com/facebookincubator/nvdtools v0.1.5
	github.com/fatih/color v1.15.0
	github.com/go-git/go-billy/v5 v5.4.1
	github.com/go-git/go-git v4.7.0+incompatible
	github.com/go-git/go-git/v5 v5.7.0
	github.com/google/go-cmp v0.5.9
	github.com/google/go-containerregistry v0.15.2
	github.com/google/go-github/v50 v50.2.0
	github.com/google/uuid v1.3.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-version v1.6.0
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/openvex/go-vex v0.2.0
	github.com/openvex/vexctl v0.2.1-0.20230407231622-35f56dd77d36
	github.com/package-url/packageurl-go v0.1.1-0.20220203205134-d70459300c8a
	github.com/pkg/errors v0.9.1
	github.com/samber/lo v1.38.1
	github.com/savioxavier/termlink v1.2.1
	github.com/sigstore/cosign/v2 v2.0.3-0.20230425232139-17cc13812d8a
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.8.4
	github.com/tmc/dot v0.0.0-20210901225022-f9bc17da75c0
	gitlab.alpinelinux.org/alpine/go v0.7.1-0.20230522152417-bbb20ba03a25
	go.lsp.dev/uri v0.3.0
	golang.org/x/exp v0.0.0-20230321023759-10a507213a29
	golang.org/x/oauth2 v0.8.0
	golang.org/x/sync v0.2.0
	golang.org/x/text v0.9.0
	golang.org/x/time v0.3.0
	google.golang.org/api v0.125.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.26.4
	k8s.io/apimachinery v0.26.4
	k8s.io/client-go v11.0.1-0.20190805182717-6502b5e7b1b5+incompatible
	k8s.io/utils v0.0.0-20230220204549-a5ecb0141aa5
	sigs.k8s.io/release-sdk v0.10.0
	sigs.k8s.io/release-utils v0.7.5-0.20230601212346-3866fe05b204
)

require (
	cloud.google.com/go v0.110.2 // indirect
	cloud.google.com/go/compute v1.20.0 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v0.13.0 // indirect
	filippo.io/edwards25519 v1.0.0 // indirect
	github.com/AliyunContainerService/ack-ram-tool/pkg/credentials/alibabacloudsdkgo/helper v0.2.0 // indirect
	github.com/Azure/azure-sdk-for-go v68.0.0+incompatible // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.29 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.22 // indirect
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.12 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.6 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/MakeNowJust/heredoc v1.0.0 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20230528122434-6f98819771a1 // indirect
	github.com/ThalesIgnite/crypto11 v1.2.5 // indirect
	github.com/acomagu/bufpipe v1.0.4 // indirect
	github.com/alibabacloud-go/alibabacloud-gateway-spi v0.0.4 // indirect
	github.com/alibabacloud-go/cr-20160607 v1.0.1 // indirect
	github.com/alibabacloud-go/cr-20181201 v1.0.10 // indirect
	github.com/alibabacloud-go/darabonba-openapi v0.2.1 // indirect
	github.com/alibabacloud-go/debug v0.0.0-20190504072949-9472017b5c68 // indirect
	github.com/alibabacloud-go/endpoint-util v1.1.1 // indirect
	github.com/alibabacloud-go/openapi-util v0.1.0 // indirect
	github.com/alibabacloud-go/tea v1.1.20 // indirect
	github.com/alibabacloud-go/tea-utils v1.4.5 // indirect
	github.com/alibabacloud-go/tea-xml v1.1.2 // indirect
	github.com/aliyun/credentials-go v1.2.4 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/avast/retry-go v3.0.0+incompatible // indirect
	github.com/aws/aws-sdk-go-v2 v1.18.0 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.18.25 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.13.24 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.13.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.33 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecr v1.18.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecrpublic v1.15.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.27 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.19.0 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/awslabs/amazon-ecr-credential-helper/ecr-login v0.0.0-20230110223219-40efa3093a22 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/benbjohnson/clock v1.3.0 // indirect
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/buildkite/agent/v3 v3.45.0 // indirect
	github.com/chrismellard/docker-credential-acr-env v0.0.0-20221129204813-6a4d6ed5d396 // indirect
	github.com/clbanning/mxj/v2 v2.5.7 // indirect
	github.com/cloudflare/circl v1.3.3 // indirect
	github.com/common-nighthawk/go-figure v0.0.0-20210622060536-734e95fb86be // indirect
	github.com/containerd/console v1.0.3 // indirect
	github.com/containerd/containerd v1.7.1 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.14.3 // indirect
	github.com/coreos/go-oidc/v3 v3.6.0 // indirect
	github.com/cyberphone/json-canonicalization v0.0.0-20220623050100-57a0ce2678a7 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20221212123742-001c36b64ec3 // indirect
	github.com/digitorus/timestamp v0.0.0-20221019182153-ef3b63b79b31 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/docker/cli v24.0.2+incompatible // indirect
	github.com/docker/distribution v2.8.2+incompatible // indirect
	github.com/docker/docker v24.0.2+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.7.0 // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dominodatalab/os-release v0.0.0-20190522011736-bcdb4a3e3c2f // indirect
	github.com/emicklei/go-restful/v3 v3.10.1 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/go-chi/chi v4.1.2+incompatible // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-jose/go-jose/v3 v3.0.0 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/analysis v0.21.4 // indirect
	github.com/go-openapi/errors v0.20.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/loads v0.21.2 // indirect
	github.com/go-openapi/runtime v0.26.0 // indirect
	github.com/go-openapi/spec v0.20.9 // indirect
	github.com/go-openapi/strfmt v0.21.7 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/go-openapi/validate v0.22.1 // indirect
	github.com/go-piv/piv-go v1.11.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.14.0 // indirect
	github.com/goccy/go-yaml v1.11.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/certificate-transparency-go v1.1.4 // indirect
	github.com/google/gnostic v0.6.9 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/s2a-go v0.1.4 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/trillian v1.5.2 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.3 // indirect
	github.com/googleapis/gax-go/v2 v2.10.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/ijt/goparsify v0.0.0-20221203142333-3a5276334b8d // indirect
	github.com/imdario/mergo v0.3.16 // indirect
	github.com/in-toto/in-toto-golang v0.9.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jedisct1/go-minisign v0.0.0-20211028175153-1c139d1cc84b // indirect
	github.com/jinzhu/copier v0.3.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/jwalton/go-supportscolor v1.1.0 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.16.5 // indirect
	github.com/korovkin/limiter v0.0.0-20230101005513-bfac7ca56b5a // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/letsencrypt/boulder v0.0.0-20230605171119-2041e8723b28 // indirect
	github.com/lima-vm/lima v0.16.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mozillazg/docker-credential-acr-helper v0.3.0 // indirect
	github.com/muesli/ansi v0.0.0-20211018074035-2e021307bc4b // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/muesli/termenv v0.15.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0-rc3 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/owenrumney/go-sarif v1.1.1 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pelletier/go-toml/v2 v2.0.7 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/psanford/memfs v0.0.0-20230130182539-4dbf7e3e865e // indirect
	github.com/rivo/uniseg v0.4.3 // indirect
	github.com/russross/blackfriday v1.6.0 // indirect
	github.com/sahilm/fuzzy v0.1.0 // indirect
	github.com/sassoftware/relic v7.2.1+incompatible // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.6.0 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	github.com/sergi/go-diff v1.3.1 // indirect
	github.com/shibumi/go-pathspec v1.3.0 // indirect
	github.com/sigstore/fulcio v1.2.0 // indirect
	github.com/sigstore/protobuf-specs v0.1.0 // indirect
	github.com/sigstore/rekor v1.2.1 // indirect
	github.com/sigstore/sigstore v1.6.5 // indirect
	github.com/sigstore/sigstore/pkg/signature/kms/aws v1.6.5 // indirect
	github.com/sigstore/sigstore/pkg/signature/kms/azure v1.6.5 // indirect
	github.com/sigstore/sigstore/pkg/signature/kms/gcp v1.6.5 // indirect
	github.com/sigstore/sigstore/pkg/signature/kms/hashivault v1.6.5 // indirect
	github.com/sigstore/timestamp-authority v1.0.0 // indirect
	github.com/skeema/knownhosts v1.1.1 // indirect
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966 // indirect
	github.com/spf13/afero v1.9.3 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/viper v1.15.0 // indirect
	github.com/spiffe/go-spiffe/v2 v2.1.4 // indirect
	github.com/src-d/gcfg v1.4.0 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20220721030215-126854af5e6d // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	github.com/theupdateframework/go-tuf v0.5.2 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	github.com/vbatts/tar-split v0.11.3 // indirect
	github.com/xanzy/go-gitlab v0.83.0 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xorcare/pointer v1.2.2 // indirect
	github.com/yookoala/realpath v1.0.0 // indirect
	github.com/zclconf/go-cty v1.12.1 // indirect
	github.com/zealic/xignore v0.3.3 // indirect
	github.com/zeebo/errs v1.3.0 // indirect
	go.mongodb.org/mongo-driver v1.11.6 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/otel v1.15.0 // indirect
	go.opentelemetry.io/otel/trace v1.15.0 // indirect
	go.step.sm/crypto v0.30.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/build v0.0.0-20230605164246-ca817f61f80c // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/mod v0.10.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/term v0.8.0 // indirect
	golang.org/x/tools v0.9.3 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230530153820-e85fd2cbaebc // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230530153820-e85fd2cbaebc // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230530153820-e85fd2cbaebc // indirect
	google.golang.org/grpc v1.55.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/src-d/go-git.v4 v4.13.1 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/klog/v2 v2.100.1 // indirect
	k8s.io/kube-openapi v0.0.0-20230123170611-3dfa6bdaa2d5 // indirect
	mvdan.cc/sh/v3 v3.5.1 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)
