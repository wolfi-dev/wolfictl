#!/usr/bin/env bash

set -euo pipefail

SECRET_NAME="${SIGNING_SECRET_NAME:-melange-signing-key}"

if [ $# -lt 1 ]; then
  echo "Must specify service account name"
fi
SA=${1}

# Bind the default KSA to the build GSA
kubectl annotate serviceaccount default --overwrite \
  "iam.gke.io/gcp-service-account=${SA}@${PROJECT}.iam.gserviceaccount.com"

# Install the secrets store CSI driver.
CSI_DRIVER_VERSION=1.3.3
kubectl apply \
  -f "https://raw.githubusercontent.com/kubernetes-sigs/secrets-store-csi-driver/v${CSI_DRIVER_VERSION}/deploy/rbac-secretproviderclass.yaml" \
  -f "https://raw.githubusercontent.com/kubernetes-sigs/secrets-store-csi-driver/v${CSI_DRIVER_VERSION}/deploy/csidriver.yaml" \
  -f "https://raw.githubusercontent.com/kubernetes-sigs/secrets-store-csi-driver/v${CSI_DRIVER_VERSION}/deploy/secrets-store.csi.x-k8s.io_secretproviderclasses.yaml" \
  -f "https://raw.githubusercontent.com/kubernetes-sigs/secrets-store-csi-driver/v${CSI_DRIVER_VERSION}/deploy/secrets-store.csi.x-k8s.io_secretproviderclasspodstatuses.yaml" \
  -f "https://raw.githubusercontent.com/kubernetes-sigs/secrets-store-csi-driver/v${CSI_DRIVER_VERSION}/deploy/secrets-store-csi-driver.yaml"

# Replace the upstream CSI driver with our own Chainguard Image equivalent.
# If this image is not available, comment this out to use the upstream directly.
kubectl set image ds/csi-secrets-store \
  -n kube-system \
  secrets-store=cgr.dev/chainguard/secrets-store-csi-driver:${CSI_DRIVER_VERSION}

# Install the GCP provider for the secrets store CSI driver.
GCP_PLUGIN_VERSION=1.2.0
kubectl apply -f "https://raw.githubusercontent.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp/v${GCP_PLUGIN_VERSION}/deploy/provider-gcp-plugin.yaml"

# Replace the upstream GCP CSI driver with our own Chainguard Image equivalent.
# If this image is not available, comment this out to use the upstream directly.
kubectl set image daemonset/csi-secrets-store-provider-gcp \
  -n kube-system \
  provider=cgr.dev/chainguard/secrets-store-csi-driver-provider-gcp:${GCP_PLUGIN_VERSION}

# Patch the secrets store CSI driver and GCP provider to tolerate Arm nodes.
kubectl patch daemonset csi-secrets-store-provider-gcp \
  -n kube-system \
  --patch-file=scripts/arm-patch.yaml

# Wait for DaemonSets to become ready.
kubectl rollout status daemonset -n kube-system csi-secrets-store
kubectl rollout status daemonset -n kube-system csi-secrets-store-provider-gcp

# Bind the melange signing key GCP secret to the secrets store CSI driver.
cat <<EOF | kubectl apply -f -
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: melange-key
spec:
  provider: gcp
  parameters:
    secrets: |
      - resourceName: "projects/${PROJECT}/secrets/${SECRET_NAME}/versions/latest"
        path: "melange.rsa"
EOF

# Set up qemu binfmt emulation.
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: binfmt
  labels:
    app: binfmt-setup
spec:
  selector:
    matchLabels:
      name: binfmt
  template:
    metadata:
      labels:
        name: binfmt
    spec:
      tolerations:
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
      initContainers:
        - name: binfmt
          image: tonistiigi/binfmt
          args: ["--install", "all"]
          securityContext:
            privileged: true
      containers:
        - name: pause
          image: registry.k8s.io/kubernetes/pause:3.9
          resources:
            limits:
              cpu: 50m
              memory: 50Mi
            requests:
              cpu: 50m
              memory: 50Mi
EOF
