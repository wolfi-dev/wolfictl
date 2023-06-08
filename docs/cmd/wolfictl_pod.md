## wolfictl pod

Generate a kubernetes pod to run the build

### Usage

```
wolfictl pod
```

### Synopsis

Generate a kubernetes pod to run the build

### Options

```
  -a, --arch string                      architecture to build for (default "x86_64")
      --bucket string                    if set, upload contents of packages/* to a location in GCS
      --bundle-repo string               OCI repository to push the bundle to; if unset, gcr.io/$PROJECT/dag
      --cache-bundle string              if set, cache bundle reference by digest
      --cpu string                       CPU request (default "1")
      --create                           create the pod (default true)
  -d, --dir string                       directory to search for melange configs (default ".")
      --gcloud-image string              image to use for gcloud stuff (default "gcr.io/google.com/cloudsdktool/google-cloud-cli:slim")
  -h, --help                             help for pod
      --melange-build-options string     additional options to pass to the melange build
  -n, --namespace string                 namespace to create the pod in (default "default")
      --pending-timeout duration         timeout for the pod to start (default 5m0s)
      --project string                   GCP project; if unset, detects project configured by gcloud
      --public-key-bucket string         if set, uses this bucket combined with --signing-key-name to fetch the public key used to verify packages from --src-bucket.  If not set defaults to --src-bucket value
      --ram string                       RAM request (default "2Gi")
      --sdk-image string                 sdk image to use (default "ghcr.io/wolfi-dev/sdk:latest")
      --secret-key melange-signing-key   if true, bind a GCP secret named melange-signing-key into /var/secrets/melange.rsa (requires GKE and Workload Identity)
      --service-account string           service account to use (default "default")
      --signing-key-name string          the signing key name to use, the name is important when when signing e.g. keyName=wolfi-signing (default "wolfi-signing")
      --src-bucket string                if set, download contents of packages/* from a location in GCS (default "gs://wolfi-production-registry-destination/os/")
  -w, --watch                            watch the pod, stream logs (default true)
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi

