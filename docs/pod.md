# Running builds on Kubernetes

Prerequisites:
- a Kubernetes cluster (KinD, GKE)
- a container image repo, which you set to the `REPO` env var (e.g., `REPO=gcr.io/jason-chainguard/wolfictl`)

If running on KinD the image has to be publicly-readable.
If running on GKE the image has to be in GCR/AR, in the same project as the cluster.

> ⚠️ GKE Autopilot is not currently supported, due to bubblewrap requiring `--privileged`.

To create a suitable GKE cluster:

```
export PROJECT=$(gcloud config get-value project)
```

```
gcloud container clusters create tmp-cluster \
    --zone            us-central1-b  \
    --enable-autoprovisioning \
    --release-channel rapid \
    --workload-pool="${PROJECT}.svc.id.goog" \
    --max-cpu=100 --max-memory=100 \
    --num-nodes=1
```

## Getting Started

Run pod that executes `make all` on the current directory:

```
wolfictl pod
```

This will create a Pod with a unique generated name to `make all`, watch it until it starts, and tail logs.

If Pod creation or initialization fails, or if the build running in the Pod fails, the command fails.

You can specify a subset of packages to build as positional args, e.g., `wolfictl pod brotli git-lfs`

You can pass `--watch=false` to only create the Pod and not watch it.
You can pass `--create=false` to print the Pod YAML but not create it.

By default the Pod is created in the `default` namespace.
Use `--namespace` (`-n`) to change this.

## Workload Identity (GKE)

- https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity


Create a Google Service Account (GSA) -- in this example, we'll call the SA `build-cluster`.

```
gcloud iam service-accounts create build-cluster
```

Grant the GSA permission to write to Google Cloud Storage

```
gcloud projects add-iam-policy-binding ${PROJECT} \
    --member "serviceAccount:build-cluster@${PROJECT}.iam.gserviceaccount.com" \
    --role   roles/storage.admin
```

Bind the GSA to the Kubernetes Service Account (KSA)

```
gcloud iam service-accounts add-iam-policy-binding \
    build-cluster@${PROJECT}.iam.gserviceaccount.com \
    --role    roles/iam.workloadIdentityUser \
    --member "serviceAccount:${PROJECT}.svc.id.goog[default/default]"
```

Annotate the KSA to tell it which GSA it's bound to.

```
kubectl annotate serviceaccount default --overwrite \
    "iam.gke.io/gcp-service-account=build-cluster@${PROJECT}.iam.gserviceaccount.com"
```

Now when you run the Pod, it can interact with GCS with the GSA's permissions.

To grant the GSA permission to write to a bucket:

```
gsutil iam ch \
  serviceAccount:build-cluster@${PROJECT}.iam.gserviceaccount.com:objectCreator \
  gs://${BUCKET}
```

Then you can run `wolfictl pod` with `--bucket=${BUCKET}`.

You can change the KSA name with the `--service-account` flag -- if you do this, or change `--namespace`, make sure you bind the GSA to the correct KSA, and annotate the KSA!

## Signing Secret (GKE)

This depends on [Workload Identity](#workload-identity-gke)

First, put the signing key you want to use (or already have one) in Secret Manager, named `melange-signing-key`:

```
gcloud secrets create melange-signing-key --replication-policy=automatic
gcloud secrets versions add melange-signing-key --data-file="melange.rsa"
```

Grant the GSA you created above access to use the secret:

```
gcloud secrets add-iam-policy-binding melange-signing-key \
    --member=serviceAccount:build-cluster@${PROJECT}.iam.gserviceaccount.com \
    --role=roles/secretmanager.secretAccessor
```

Then run `./scripts/setup-cluster.sh build-cluster`.

This will:

1. ensure the KSA is annotated with the GSA's ID
1. install the [K8s Secrets Store CSI driver](https://secrets-store-csi-driver.sigs.k8s.io/)
1. install the [GCP plugin for the K8s Secret Store CSI driver](https://github.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp)
1. apply the necessary patches so these DaemonSets tolerate Arm nodes 
1. configure the `melange-signing-key` secret in the Secret Store CSI driver

After this, you can test that the secret is available:

```
cat <<EOF | kubectl create -f -
apiVersion: v1
kind: Pod
metadata:
  generateName: secret-test-
spec:
  serviceAccountName: default
  restartPolicy: Never
  containers:
  - image: busybox
    name: test
    command: ['ls', '/var/secrets/melange.rsa']
    volumeMounts:
      - mountPath: "/var/secrets"
        name: melange-key
  volumes:
  - name: melange-key
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: "melange-key"
EOF
```

```
$ kubectl get pods
NAME                READY   STATUS              RESTARTS   AGE
secret-test-k6pnm   0/1     Completed           0          8s
```

If it didn't complete successfully, `kubectl describe` it to troubleshoot.

With all that set up, you can now run `wolfictl pod --secret-key`, which will fetch and mount the `melange.rsa` secret and use it during the build.

## Arm Nodes (GKE)

- https://cloud.google.com/kubernetes-engine/docs/how-to/prepare-arm-workloads-for-deployment

_Note: This doesn't currently work to build wolfi, since stage3 packages are not available for arm64 yet._

Add Arm nodes to an existing cluster:

```
gcloud container node-pools create arm-nodes \
    --cluster        tmp-cluster \
    --zone           us-central1-b \
    --machine-type   t2a-standard-32 \
    --num-nodes      1
```

(Arm nodes currently require `us-central1` and a recent Kubernetes version, which you get from the Rapid release channel.
Arm nodes do not currently support auto-provisioning, so these nodes will just be on -- and charging money -- all the time.
Delete this node pool when you don't use it.)

Then request an arm64 build and see logs:

```
wolfictl pod --arch=arm64
```

Cleanup the cluster:

```
gcloud container clusters delete tmp-cluster --region=us-central1
```

## Resource Requests

By default, build pods have 1 CPU and 2 GB or memory.

You can request more, for example `wolfictl pod --cpu=4 --ram=12Gi ...`

Note: Check the nodes you configured for the cluster, to make sure you're not requesting a Pod that won't fit on any nodes.

## Pre-caching remote dependencies

You can pre-fetch `uri`s defined in the pipelines, and add them to your build.

Eventually this will aid in hermetic builds, see:
- https://github.com/chainguard-dev/melange/pull/143
- https://github.com/chainguard-dev/melange/pull/145

To populate the cache:

```
wolfictl cache
```

This will pull and verify all the URLs, and put them in `./cache`.

You can also pass `--bundle-repo` to push a bundle image containing the pre-cached dependencies.

You can pass this to a build, with `--cache-bundle`, which will pull the image and pre-populate `/var/cache/melange` in the build context with your cached dependencies.
