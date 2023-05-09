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
CSI_DRIVER_VERSION=v1.2.4
kubectl apply \
  -f "https://raw.githubusercontent.com/kubernetes-sigs/secrets-store-csi-driver/${CSI_DRIVER_VERSION}/deploy/rbac-secretproviderclass.yaml" \
  -f "https://raw.githubusercontent.com/kubernetes-sigs/secrets-store-csi-driver/${CSI_DRIVER_VERSION}/deploy/csidriver.yaml" \
  -f "https://raw.githubusercontent.com/kubernetes-sigs/secrets-store-csi-driver/${CSI_DRIVER_VERSION}/deploy/secrets-store.csi.x-k8s.io_secretproviderclasses.yaml" \
  -f "https://raw.githubusercontent.com/kubernetes-sigs/secrets-store-csi-driver/${CSI_DRIVER_VERSION}/deploy/secrets-store.csi.x-k8s.io_secretproviderclasspodstatuses.yaml" \
  -f "https://raw.githubusercontent.com/kubernetes-sigs/secrets-store-csi-driver/${CSI_DRIVER_VERSION}/deploy/secrets-store-csi-driver.yaml"

# Install the GCP provider for the secrets store CSI driver.
GCP_PLUGIN_VERSION=v1.1.0
kubectl apply -f "https://raw.githubusercontent.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp/${GCP_PLUGIN_VERSION}/deploy/provider-gcp-plugin.yaml"

# Patch the secrets store CSI driver and GCP provider to tolerate Arm nodes.
kubectl patch daemonset csi-secrets-store-provider-gcp \
  -n kube-system \
  --patch-file=arm-patch-1.yaml
kubectl patch daemonset csi-secrets-store \
  -n kube-system \
  --patch-file=arm-patch-2.yaml

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
          image: gcr.io/google_containers/pause
          resources:
            limits:
              cpu: 50m
              memory: 50Mi
            requests:
              cpu: 50m
              memory: 50Mi
EOF
