package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	gotemplate "text/template"
	"time"

	"chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/kontext"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/dag"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp" // Implicit GCP auth.
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/pointer"
)

var rootUser int64 // 0

func gcloudProjectID(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "gcloud", "config", "get-value", "project")
	b, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSuffix(b, []byte{'\n'})), nil // Trim trailing newline.
}

func cmdPod() *cobra.Command {
	var dir, arch, project, bundleRepo, ns, cpu, ram, sa, sdkimg, gcloudImage, cachedig, bucket, srcBucket, publicKeyBucket, signingKeyName, melangeBuildOpts string

	var create, watch, secretKey bool
	var pendingTimeout time.Duration

	pod := &cobra.Command{
		Use:   "pod",
		Short: "Generate a kubernetes pod to run the build",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Don't use cmd.Context() since we want to capture signals to kill the pod.
			ctx := context.Background()

			arch := types.ParseArchitecture(arch).ToAPK()

			if (bundleRepo == "" || secretKey) && project == "" {
				var err error
				project, err = gcloudProjectID(ctx)
				if err != nil {
					return fmt.Errorf("error detecting project ID: %w", err)
				}
				log.Println("Detected project is", project)
			}
			if bundleRepo == "" {
				bundleRepo = fmt.Sprintf("gcr.io/%s/dag", project)
				log.Println("Bundle repo is", bundleRepo)
			}

			targets := []string{"all"}
			if len(args) > 0 {
				pkgs, err := dag.NewPackages(os.DirFS(dir), dir)
				if err != nil {
					return err
				}
				g, err := dag.NewGraph(pkgs)
				if err != nil {
					return err
				}

				subgraph, err := g.SubgraphWithRoots(args)
				if err != nil {
					return err
				}

				targets = nil
				for _, node := range subgraph.Packages() {
					pkg, err := pkgs.PkgInfo(node)
					if err != nil {
						return err
					}
					if pkg == nil {
						continue
					}
					targets = append(targets, makeTarget(node, arch, pkg))
				}
			}

			// Bundle the source context into an image.
			t, err := name.NewTag(bundleRepo, name.WeakValidation)
			if err != nil {
				return err
			}
			dig, err := kontext.Bundle(ctx, dir, t)
			if err != nil {
				return err
			}
			log.Println("bundled source context to", dig)

			// default publicKeyBucket to source bucket if not set
			if publicKeyBucket == "" {
				publicKeyBucket = srcBucket
			}
			p := &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "dag-",
					Namespace:    ns,
				},
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: sa,
					InitContainers: []corev1.Container{{
						Name:       "init",
						Image:      dig.String(),
						WorkingDir: "/workspace",
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "workspace",
							MountPath: "/workspace",
						}},
						Resources: corev1.ResourceRequirements{
							// Minimums required by Autopilot.
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:              resource.MustParse("1"),
								corev1.ResourceMemory:           resource.MustParse("2Gi"),
								corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
							},
						},
					}, {
						Name:       "fetch-packages",
						Image:      gcloudImage,
						WorkingDir: "/workspace",
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "workspace",
							MountPath: "/workspace",
						}},
						SecurityContext: &corev1.SecurityContext{RunAsUser: &rootUser},
						Command: []string{"bash", "-c", template(`
set -euo pipefail
# Download all packages so we can avoid rebuilding them.
mkdir -p ./packages/{{.arch}}
gsutil -m rsync -r {{.bucket}}{{.arch}} ./packages/{{.arch}} || true
gsutil cp {{.publicKeyBucket}}{{.signingKeyName}}.rsa.pub .
`, map[string]string{
							"arch":            arch,
							"bucket":          srcBucket,
							"publicKeyBucket": publicKeyBucket,
							"signingKeyName":  signingKeyName,
						})},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								// Minimums required by Autopilot.
								corev1.ResourceCPU:              resource.MustParse("1"),
								corev1.ResourceMemory:           resource.MustParse("2Gi"),
								corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
							},
						},
					}},
					Containers: []corev1.Container{{
						Name:       "build",
						Image:      sdkimg,
						WorkingDir: "/workspace",
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "workspace",
							MountPath: "/workspace",
						}, {
							Name:      "cache",
							MountPath: "/var/cache/melange",
						}, {
							Name:      "tmp",
							MountPath: "/tmp",
						}},
						SecurityContext: &corev1.SecurityContext{
							Privileged: pointer.Bool(true),
						},
						Command: []string{"sh", "-c", template(`
set -euo pipefail
ls /var/cache/melange
if [[ ! -f /var/secrets/melange.rsa ]]; then
  echo "Generating key..."
  MELANGE=/usr/bin/melange KEY=melange.rsa make melange.rsa
  KEY=melange.rsa
else
  echo "Using secret key..."
  cp /var/secrets/melange.rsa {{.signingKeyName}}.rsa
  KEY={{.signingKeyName}}.rsa
  ls {{.signingKeyName}}.rsa
fi

# In order to run "git log" on the packaged .git metadata we need to
# make sure that we don't hit "dubious permission" errors.
git config --global --add safe.directory /workspace

set +e # Always touch start-gcloud-cp to start uploading buitl packages, even if the build fails.
find ./packages -print -exec touch \{} \;
MELANGE=/usr/bin/melange MELANGE_DIR=/usr/share/melange KEY=${KEY} ARCH={{.arch}} REPO=./packages MELANGE_EXTRA_OPTS="{{.melangeBuildOpts}}" make {{.targets}}
success=$?
rm ${KEY}
touch start-gcloud-cp
echo exiting $success...
exit $success
`, map[string]string{
							"signingKeyName":   signingKeyName,
							"arch":             arch,
							"targets":          strings.Join(targets, " "),
							"melangeBuildOpts": melangeBuildOpts,
						})},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:              resource.MustParse(cpu),
								corev1.ResourceMemory:           resource.MustParse(ram),
								corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
							},
						},
					}},
					Volumes: []corev1.Volume{{
						Name: "workspace",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					}, {
						Name: "cache",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					}, {
						Name: "tmp",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					}},
				},
			}

			// If the user specified a cache bundle image, run it as an init
			// container, which will populate the cache volume for the build container.
			if cachedig != "" {
				p.Spec.InitContainers = append(p.Spec.InitContainers, corev1.Container{
					Name:       "populate-cache",
					Image:      cachedig,
					WorkingDir: "/var/cache/melange",
					VolumeMounts: []corev1.VolumeMount{{
						Name:      "cache",
						MountPath: "/var/cache/melange",
					}},
				})
			}

			if bucket != "" {
				p.Spec.Containers = append(p.Spec.Containers, corev1.Container{
					Name:       "gcloud-cp",
					Image:      gcloudImage,
					WorkingDir: "/workspace",
					Command: []string{"sh", "-c", template(`
#!/usr/bin/env bash
interval=10
while true;
do
  [ -f start-gcloud-cp ] && break
  sleep $interval
done

# Don't cache the APKINDEX, and leave it public if it already is.
gcloud --quiet storage cp \
	--cache-control=no-store \
	--preserve-acl \
	"./packages/{{.arch}}/APKINDEX.tar.gz" gs://{{.bucket}}{{.arch}}/ || true

# apks will be cached in CDN for an hour by default.
gcloud --quiet storage cp \
	"./packages/{{.arch}}/*.apk" gs://{{.bucket}}{{.arch}}/ || true
`, map[string]string{"bucket": bucket, "arch": arch}),
					},
					Resources: corev1.ResourceRequirements{
						// Minimums required by Autopilot.
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:              resource.MustParse("1"),
							corev1.ResourceMemory:           resource.MustParse("2Gi"),
							corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{{
						Name:      "workspace",
						MountPath: "/workspace",
					}},
				})
			}

			if secretKey {
				// TODO: Make sure the SecretProviderClass exists.
				p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
					Name:      "melange-key",
					MountPath: "/var/secrets",
				})
				p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{
					Name: "melange-key",
					VolumeSource: corev1.VolumeSource{
						CSI: &corev1.CSIVolumeSource{
							Driver:   "secrets-store.csi.k8s.io",
							ReadOnly: pointer.Bool(true),
							VolumeAttributes: map[string]string{
								"secretProviderClass": "melange-key",
							},
						},
					},
				})
			}

			if arch == "aarch64" {
				p.Spec.NodeSelector = map[string]string{
					// "cloud.google.com/compute-class": "Scale-Out", TODO(jason): Needed for GKE Autopilot.
					"kubernetes.io/arch": "arm64",
				}
			}

			if create {
				k8s, err := newK8s(pendingTimeout, bucket)
				if err != nil {
					return err
				}
				p, err = k8s.create(ctx, p)
				if err != nil {
					return err
				}
				log.Println("created pod:", p.Name)
				if watch {
					return k8s.watch(ctx, p)
				}
				return nil
			}

			return json.NewYAMLSerializer(json.DefaultMetaFactory, nil, nil).Encode(p, os.Stdout)
		},
	}
	pod.Flags().StringVarP(&dir, "dir", "d", ".", "directory to search for melange configs")
	pod.Flags().StringVarP(&arch, "arch", "a", "x86_64", "architecture to build for")
	pod.Flags().StringVar(&bundleRepo, "bundle-repo", "", "OCI repository to push the bundle to; if unset, gcr.io/$PROJECT/dag")
	pod.Flags().StringVar(&project, "project", "", "GCP project; if unset, detects project configured by gcloud")
	pod.Flags().StringVarP(&ns, "namespace", "n", "default", "namespace to create the pod in")
	pod.Flags().StringVar(&cpu, "cpu", "1", "CPU request")
	pod.Flags().StringVar(&ram, "ram", "2Gi", "RAM request")
	pod.Flags().StringVar(&sa, "service-account", "default", "service account to use")
	pod.Flags().BoolVar(&create, "create", true, "create the pod")
	pod.Flags().BoolVarP(&watch, "watch", "w", true, "watch the pod, stream logs")
	pod.Flags().StringVar(&sdkimg, "sdk-image", "ghcr.io/wolfi-dev/sdk:latest", "sdk image to use") // alpine-based, but supports arm64
	pod.Flags().DurationVar(&pendingTimeout, "pending-timeout", 5*time.Minute, "timeout for the pod to start")
	pod.Flags().StringVar(&cachedig, "cache-bundle", "", "if set, cache bundle reference by digest")
	pod.Flags().BoolVar(&secretKey, "secret-key", false, "if true, bind a GCP secret named `melange-signing-key` into /var/secrets/melange.rsa (requires GKE and Workload Identity)")
	pod.Flags().StringVar(&bucket, "bucket", "", "if set, upload contents of packages/* to a location in GCS")
	pod.Flags().StringVar(&srcBucket, "src-bucket", "gs://wolfi-production-registry-destination/os/", "if set, download contents of packages/* from a location in GCS")
	pod.Flags().StringVar(&publicKeyBucket, "public-key-bucket", "", "if set, uses this bucket combined with --signing-key-name to fetch the public key used to verify packages from --src-bucket.  If not set defaults to --src-bucket value")
	pod.Flags().StringVar(&signingKeyName, "signing-key-name", "wolfi-signing", "the signing key name to use, the name is important when when signing e.g. keyName=wolfi-signing")
	pod.Flags().StringVar(&melangeBuildOpts, "melange-build-options", "", "additional options to pass to the melange build")
	pod.Flags().StringVar(&gcloudImage, "gcloud-image", "gcr.io/google.com/cloudsdktool/google-cloud-cli:slim", "image to use for gcloud stuff")

	_ = pod.MarkFlagRequired("repo") //nolint:errcheck
	return pod
}

type k8s struct {
	clientset      kubernetes.Clientset
	pendingTimeout time.Duration
	started        bool
	bucket         string
}

func newK8s(pendingTimeout time.Duration, bucket string) (*k8s, error) {
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &k8s{
		clientset:      *clientset,
		pendingTimeout: pendingTimeout,
		bucket:         bucket,
	}, nil
}

func (k *k8s) create(ctx context.Context, p *corev1.Pod) (*corev1.Pod, error) {
	return k.clientset.CoreV1().Pods(p.Namespace).Create(ctx, p, metav1.CreateOptions{})
}

func (k *k8s) watch(ctx context.Context, p *corev1.Pod) error {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-c:
			log.Println("interrupted, deleting pod")
			// TODO: Prompt to delete the pod.
			if err := k.clientset.CoreV1().Pods(p.Namespace).Delete(context.Background(), p.Name, metav1.DeleteOptions{}); err != nil {
				log.Println("failed to delete pod:", err)
			}
			// TODO: Wait for pod to be deleted.
			log.Println("deleted pod: ", p.Name)
			os.Exit(1)
		case <-ctx.Done():
			return
		}
	}()

	w, err := k.clientset.CoreV1().Pods(p.Namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=" + p.Name,
	})
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(k.pendingTimeout):
			if !k.started {
				// TODO: Prompt to delete the pod.
				// TODO: Wait for pod to be deleted.
				return fmt.Errorf("timed out waiting for pod to start")
			}
		case e := <-w.ResultChan():
			var ok bool
			p, ok = e.Object.(*corev1.Pod)
			if !ok {
				if st, ok := e.Object.(*metav1.Status); ok {
					log.Println("saw watch update with status:", st.Message)
					continue
				}
				return fmt.Errorf("unexpected object type: %T", e.Object)
			}
			switch p.Status.Phase {
			case corev1.PodPending:
				s := p.Status
				if len(s.InitContainerStatuses) > 0 && s.InitContainerStatuses[0].State.Running != nil {
					log.Println("init container running")
					continue
				}
				if len(s.ContainerStatuses) > 0 && s.ContainerStatuses[0].State.Waiting != nil {
					log.Println("build container waiting:", p.Status.ContainerStatuses[0].State.Waiting.Reason)
					continue
				}
				log.Println("pending...")
				time.Sleep(time.Second)
			case corev1.PodRunning:
				log.Printf("running... took %s", time.Since(p.CreationTimestamp.Time))
				k.started = true

				// Start streaming logs.
				var errg errgroup.Group
				stream := func(container string) func() error {
					return func() error {
						rc, err := k.clientset.CoreV1().Pods(p.Namespace).GetLogs(p.Name, &corev1.PodLogOptions{
							Container: container,
							Follow:    true,
						}).Stream(ctx)
						if err != nil {
							return err
						}
						defer rc.Close()
						_, err = io.Copy(os.Stdout, rc)
						return err
					}
				}
				errg.Go(stream("build"))
				if k.bucket != "" {
					errg.Go(stream("gcloud-cp"))
				}
				if err := errg.Wait(); err != nil {
					return err
				}

				log.Println("log streaming done")

				// With log streaming done, poll until the Pod reports as Succeeded, or fail otherwise.
				// Sometimes even when the containers are Completed successfully,
				// the Pod doesn't say it's Succeeded for a little bit, and we shouldn't fail in that case.
				if err := wait.PollImmediate(5*time.Second, time.Minute, func() (bool, error) {
					p, err = k.clientset.CoreV1().Pods(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
					if err != nil {
						return true, err
					}
					log.Println("=== STATUS")
					if err := yaml.NewEncoder(os.Stderr).Encode(p.Status); err != nil {
						return true, err
					}
					return p.Status.Phase == corev1.PodSucceeded, nil
				}); err != nil {
					return err
				}
				log.Printf("succeeded! took %s", time.Since(p.CreationTimestamp.Time).Round(time.Second))
				return nil

			case corev1.PodSucceeded:
				log.Printf("succeeded! took %s", time.Since(p.CreationTimestamp.Time).Round(time.Second))
				return nil
			case corev1.PodFailed:
				log.Println("failed!")
				log.Println("=== STATUS")
				if err := yaml.NewEncoder(os.Stderr).Encode(p.Status); err != nil {
					return err
				}
				return errors.New("pod failed")
			case corev1.PodUnknown:
				log.Println("unknown status...")
				log.Println("=== STATUS")
				if err := yaml.NewEncoder(os.Stderr).Encode(p.Status); err != nil {
					return err
				}
			default:
				log.Println("=== STATUS")
				if err := yaml.NewEncoder(os.Stderr).Encode(p.Status); err != nil {
					return err
				}
				return fmt.Errorf("unknown phase: %s", p.Status.Phase)
			}
		}
	}
}

func template(tmpl string, data map[string]string) string {
	var buf bytes.Buffer
	t := gotemplate.Must(gotemplate.New("").Parse(tmpl))
	t.Option("missingkey=error")
	if err := t.Execute(&buf, data); err != nil {
		log.Fatalf("Executing template: %v", err)
	}
	return buf.String()
}
