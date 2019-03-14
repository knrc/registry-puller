package webhook

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/ghodss/yaml"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/hashicorp/go-multierror"

	"github.com/howeyc/fsnotify"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	"k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	clientset "k8s.io/client-go/kubernetes"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

func init() {
	_ = v1beta1.AddToScheme(runtimeScheme)
}

const (
	watchDebounceDelay = 100 * time.Millisecond

	httpsHandlerReadyPath string = "/ready"
)

type PullerWebhookParameters struct {
	// Webhook port
	Port uint

	// CACertFile is the path to the x509 CA bundle file.
	CACertFile string

	// CertFile is the path to the x509 certificate for https.
	CertFile string

	// KeyFile is the path to the x509 private key matching `CertFile`.
	KeyFile string

	// WebhookConfigFile is the path to the mutatingwebhookconfiguration
	WebhookConfigFile string

	// Namespace is the namespace in which the deployment and service resides.
	Namespace string

	// Name of the webhook
	WebhookName string

	// The webhook deployment name
	DeploymentName string

	// RegistrySecretFile is the name of the yaml file containing the registry secret
	RegistrySecretFile string

	Clientset clientset.Interface
}

type Webhook struct {
	mu   sync.RWMutex
	cert *tls.Certificate

	server               *http.Server
	keyCertWatcher       *fsnotify.Watcher
	configWatcher        *fsnotify.Watcher
	caFile               string
	certFile             string
	keyFile              string
	webhookConfigFile    string
	clientset            clientset.Interface
	namespace            string
	deploymentName       string
	registrySecretFile   string
	webhookName          string
	ownerRefs            []metav1.OwnerReference
	webhookConfiguration *v1beta1.MutatingWebhookConfiguration
}

type rfc6902PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func DefaultArgs() *PullerWebhookParameters {
	return &PullerWebhookParameters{
		Port:           443,
		CertFile:       "/etc/certs/cert-chain.pem",
		KeyFile:        "/etc/certs/key.pem",
		CACertFile:     "/etc/certs/root-cert.pem",
		Namespace:      "registry-puller",
		DeploymentName: "registry-puller",
		WebhookName:    "registry-puller",
	}
}

func (p *PullerWebhookParameters) String() string {
	buf := &bytes.Buffer{}

	_, _ = fmt.Fprintf(buf, "Port: %d\n", p.Port)
	_, _ = fmt.Fprintf(buf, "CertFile: %s\n", p.CertFile)
	_, _ = fmt.Fprintf(buf, "KeyFile: %s\n", p.KeyFile)
	_, _ = fmt.Fprintf(buf, "WebhookConfigFile: %s\n", p.WebhookConfigFile)
	_, _ = fmt.Fprintf(buf, "CACertFile: %s\n", p.CACertFile)
	_, _ = fmt.Fprintf(buf, "Namespace: %s\n", p.Namespace)
	_, _ = fmt.Fprintf(buf, "WebhookName: %s\n", p.WebhookName)
	_, _ = fmt.Fprintf(buf, "DeploymentName: %s\n", p.DeploymentName)

	return buf.String()
}

// NewWebhook creates a new instance of the admission webhook controller.
func NewWebhook(p PullerWebhookParameters) (*Webhook, error) {
	pair, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
	if err != nil {
		return nil, err
	}
	certKeyWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	// watch the parent directory of the target files so we can catch
	// symlink updates of k8s secrets
	for _, file := range []string{p.CertFile, p.KeyFile, p.CACertFile, p.WebhookConfigFile} {
		watchDir, _ := filepath.Split(file)
		if err := certKeyWatcher.Watch(watchDir); err != nil {
			return nil, fmt.Errorf("could not watch %v: %v", file, err)
		}
	}

	// configuration must be updated whenever the caBundle changes.
	// NOTE: Use a separate watcher to differentiate config/ca from cert/key updates. This is
	// useful to avoid unnecessary updates and, more importantly, makes its easier to more
	// accurately capture logs/metrics when files change.
	configWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	for _, file := range []string{p.CACertFile, p.WebhookConfigFile} {
		watchDir, _ := filepath.Split(file)
		if err := configWatcher.Watch(watchDir); err != nil {
			return nil, fmt.Errorf("could not watch %v: %v", file, err)
		}
	}

	wh := &Webhook{
		server: &http.Server{
			Addr: fmt.Sprintf(":%v", p.Port),
		},
		keyCertWatcher:     certKeyWatcher,
		configWatcher:      configWatcher,
		certFile:           p.CertFile,
		keyFile:            p.KeyFile,
		cert:               &pair,
		caFile:             p.CACertFile,
		webhookConfigFile:  p.WebhookConfigFile,
		clientset:          p.Clientset,
		deploymentName:     p.DeploymentName,
		registrySecretFile: p.RegistrySecretFile,
		webhookName:        p.WebhookName,
		namespace:          p.Namespace,
	}

	if registryPullerDeployment, err := wh.clientset.ExtensionsV1beta1().Deployments(wh.namespace).Get(wh.deploymentName, metav1.GetOptions{}); err != nil {
		logError.Printf("Could not find %s/%s deployment to set ownerRef. The mutatingwebhookconfiguration must be deleted manually",
			wh.namespace, wh.deploymentName)
	} else {
		wh.ownerRefs = []metav1.OwnerReference{
			*metav1.NewControllerRef(
				registryPullerDeployment,
				extensionsv1beta1.SchemeGroupVersion.WithKind("Deployment"),
			),
		}
	}

	// mtls disabled because apiserver webhook cert usage is still TBD.
	wh.server.TLSConfig = &tls.Config{GetCertificate: wh.getCert}
	h := http.NewServeMux()
	h.HandleFunc("/webhook", wh.serve)
	h.HandleFunc(httpsHandlerReadyPath, wh.serveReady)
	wh.server.Handler = h

	return wh, nil
}

func (wh *Webhook) stop() {
	_ = wh.keyCertWatcher.Close()
	_ = wh.configWatcher.Close()
	_ = wh.server.Close()
}

// Run implements the webhook server
func (wh *Webhook) Run(stopCh <-chan struct{}) {
	go func() {
		if err := wh.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logError.Printf("admission webhook ListenAndServeTLS failed: %v", err)
		}
	}()
	defer wh.stop()

	// Try to create the initial webhook configuration (if it doesn't
	// already exist). Setup a persistent monitor to reconcile the
	// configuration if the observed configuration doesn't match
	// the desired configuration.
	if err := wh.rebuildWebhookConfig(); err == nil {
		wh.createOrUpdateWebhookConfig()
	}
	webhookChangedCh := wh.monitorWebhookChanges(stopCh)

	// use a timer to debounce file updates
	var keyCertTimerC <-chan time.Time
	var configTimerC <-chan time.Time

	for {
		select {
		case <-keyCertTimerC:
			keyCertTimerC = nil
			wh.reloadKeyCert()
		case <-configTimerC:
			configTimerC = nil

			// rebuild the desired configuration and reconcile with the
			// existing configuration.
			if err := wh.rebuildWebhookConfig(); err == nil {
				wh.createOrUpdateWebhookConfig()
			}
		case <-webhookChangedCh:
			// reconcile the desired configuration
			wh.createOrUpdateWebhookConfig()
		case event, more := <-wh.keyCertWatcher.Event:
			if more && (event.IsModify() || event.IsCreate()) && keyCertTimerC == nil {
				keyCertTimerC = time.After(watchDebounceDelay)
			}
		case event, more := <-wh.configWatcher.Event:
			if more && (event.IsModify() || event.IsCreate()) && configTimerC == nil {
				configTimerC = time.After(watchDebounceDelay)
			}
		case err := <-wh.keyCertWatcher.Error:
			logError.Printf("keyCertWatcher error: %v", err)
		case err := <-wh.configWatcher.Error:
			logError.Printf("configWatcher error: %v", err)
		case <-stopCh:
			return
		}
	}
}

func (wh *Webhook) getCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	wh.mu.Lock()
	defer wh.mu.Unlock()
	return wh.cert, nil
}

func toAdmissionResponse(err error) *admissionv1beta1.AdmissionResponse {
	status := metav1.Status{Message: err.Error()}
	return &admissionv1beta1.AdmissionResponse{Result: &status}
}

func (wh *Webhook) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		http.Error(w, "no body found", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		http.Error(w, "invalid Content-Type, want `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var reviewResponse *admissionv1beta1.AdmissionResponse
	ar := admissionv1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		reviewResponse = toAdmissionResponse(fmt.Errorf("could not decode body: %v", err))
	} else {
		reviewResponse = wh.inject(&ar)
	}

	response := admissionv1beta1.AdmissionReview{}
	if reviewResponse != nil {
		response.Response = reviewResponse
		if ar.Request != nil {
			response.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("could encode response: %v", err), http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(resp); err != nil {
		http.Error(w, fmt.Sprintf("could write response: %v", err), http.StatusInternalServerError)
	}
}

func (wh *Webhook) serveReady(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (wh *Webhook) inject(ar *admissionv1beta1.AdmissionReview) (reviewResponse *admissionv1beta1.AdmissionResponse) {
	req := ar.Request
	var sa corev1.ServiceAccount
	if err := json.Unmarshal(req.Object.Raw, &sa); err != nil {
		logError.Printf("Could not unmarshal raw object: %v %s", err,
			string(req.Object.Raw))
		return toAdmissionResponse(err)
	}

	logInfo.Printf("AdmissionReview for Kind=%v Namespace=%v Name=%v UID=%v Rfc6902PatchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, req.UID, req.Operation, req.UserInfo)

	secret, err := wh.getOrCreateSecret(req.Namespace)
	if err != nil {
		logError.Printf("Could not get or create secret in namespace %s: %v", req.Namespace, err)
		return toAdmissionResponse(err)
	}

	patch := addImagePullSecret(sa, secret.Name)

	if patch == nil {
		reviewResponse = &admissionv1beta1.AdmissionResponse{
			Allowed: true,
		}
	} else {
		patchBytes, err := json.Marshal(patch)
		if err != nil {
			logError.Printf("Could not marshall patch: %v", err)
			return toAdmissionResponse(err)
		}

		logInfo.Printf("AdmissionResponse: patch=%v\n", string(patchBytes))
		reviewResponse = &admissionv1beta1.AdmissionResponse{
			Allowed: true,
			Patch:   patchBytes,
			PatchType: func() *admissionv1beta1.PatchType {
				pt := admissionv1beta1.PatchTypeJSONPatch
				return &pt
			}(),
		}
	}
	return
}

func addImagePullSecret(account corev1.ServiceAccount, secret string) []rfc6902PatchOperation {
	var value interface{}
	path := "/imagePullSecrets"
	reference := corev1.LocalObjectReference{Name: secret}
	if account.ImagePullSecrets != nil {
		for _, imagePullSecret := range account.ImagePullSecrets {
			if imagePullSecret.Name == secret {
				return nil
			}
		}
		path = path + "/-"
		value = reference
	} else {
		value = []corev1.LocalObjectReference{reference}
	}
	return []rfc6902PatchOperation{{
		Op:    "add",
		Path:  path,
		Value: value,
	}}
}

func (wh *Webhook) getOrCreateSecret(namespace string) (*corev1.Secret, error) {
	secretData, err := ioutil.ReadFile(wh.registrySecretFile)
	if err != nil {
		return nil, err
	}
	var secret corev1.Secret
	if err := yaml.Unmarshal(secretData, &secret); err != nil {
		return nil, fmt.Errorf("could not decode secret from %v: %v",
			wh.registrySecretFile, err)
	}
	client := wh.clientset.CoreV1().Secrets(namespace)
	origSecret, err := client.Get(secret.Name, metav1.GetOptions{})
	if err != nil && k8serrors.IsNotFound(err) {
		secret.Namespace = namespace
		logInfo.Printf("Creating secret %v", secret)
		return client.Create(&secret)
	} else if err != nil {
		return nil, err
	} else {
		return origSecret, nil
	}
}

const (
	dns1123LabelMaxLength int    = 63
	dns1123LabelFmt       string = "[a-zA-Z0-9]([-a-z-A-Z0-9]*[a-zA-Z0-9])?"
)

var dns1123LabelRegexp = regexp.MustCompile("^" + dns1123LabelFmt + "$")

func isDNS1123Label(value string) bool {
	return len(value) <= dns1123LabelMaxLength && dns1123LabelRegexp.MatchString(value)
}

func validatePort(port int) error {
	if 1 <= port && port <= 65535 {
		return nil
	}
	return fmt.Errorf("port number %d must be in the range 1..65535", port)
}

// Validate tests if the PullerWebhookParameters has valid params.
func (p *PullerWebhookParameters) Validate() error {
	if p == nil {
		return errors.New("nil PullerWebhookParameters")
	}

	var errs *multierror.Error
	// Validate the options that exposed to end users
	if p.WebhookName == "" || !isDNS1123Label(p.WebhookName) {
		errs = multierror.Append(errs, fmt.Errorf("invalid webhook name: %q", p.WebhookName))
	}
	if p.DeploymentName == "" || !isDNS1123Label(p.Namespace) {
		errs = multierror.Append(errs, fmt.Errorf("invalid deployment namespace: %q", p.Namespace))
	}
	if p.DeploymentName == "" || !isDNS1123Label(p.DeploymentName) {
		errs = multierror.Append(errs, fmt.Errorf("invalid deployment name: %q", p.DeploymentName))
	}
	if len(p.WebhookConfigFile) == 0 {
		errs = multierror.Append(errs, errors.New("webhookConfigFile not specified"))
	}
	if len(p.CertFile) == 0 {
		errs = multierror.Append(errs, errors.New("cert file not specified"))
	}
	if len(p.KeyFile) == 0 {
		errs = multierror.Append(errs, errors.New("key file not specified"))
	}
	if len(p.CACertFile) == 0 {
		errs = multierror.Append(errs, errors.New("CA cert file not specified"))
	}
	if err := validatePort(int(p.Port)); err != nil {
		errs = multierror.Append(errs, err)
	}

	return errs.ErrorOrNil()
}

func buildClientConfig() (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.DefaultClientConfig = &clientcmd.DefaultClientConfig
	configOverrides := &clientcmd.ConfigOverrides{
		ClusterDefaults: clientcmd.ClusterDefaults,
	}

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
}

func createClientset() (*kubernetes.Clientset, error) {
	config, err := buildClientConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

func RunWebhook(wp *PullerWebhookParameters, stop chan struct{}) {
	logInfo.Printf("Webhook started with\n%s", wp)
	cs, err := createClientset()
	if err != nil {
		logError.Printf("cannot create webhook service: %v", err)
	} else {
		wp.Clientset = cs
		wh, err := NewWebhook(*wp)
		if err != nil {
			logError.Printf("cannot create webhook service: %v", err)
		} else {
			go wh.Run(stop)
		}
	}
}
