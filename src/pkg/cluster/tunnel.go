// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package cluster contains Zarf-specific cluster management functions.
package cluster

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"github.com/avast/retry-go/v4"
	"github.com/defenseunicorns/pkg/helpers/v2"
	"github.com/zarf-dev/zarf/src/internal/dns"
	"github.com/zarf-dev/zarf/src/pkg/logger"
	"github.com/zarf-dev/zarf/src/pkg/state"
)

// Zarf specific connect strings
const (
	ZarfConnectLabelName             = "zarf.dev/connect-name"
	ZarfConnectAnnotationDescription = "zarf.dev/connect-description"
	ZarfConnectAnnotationURL         = "zarf.dev/connect-url"

	ZarfRegistry = "REGISTRY"
	ZarfGit      = "GIT"
	ZarfInjector = "INJECTOR"

	ZarfInjectorName  = "zarf-injector"
	ZarfInjectorPort  = 5000
	ZarfRegistryName  = "zarf-docker-registry"
	ZarfRegistryPort  = 5000
	ZarfGitServerName = "zarf-gitea-http"
	ZarfGitServerPort = 3000
)

// TunnelInfo is a struct that contains the necessary info to create a new Tunnel
type TunnelInfo struct {
	LocalPort       int
	RemotePort      int
	ListenAddresses []string
	Namespace       string
	ResourceType    string
	ResourceName    string
	urlSuffix       string
}

// ListConnections will return a list of all Zarf connect matches found in the cluster.
func (c *Cluster) ListConnections(ctx context.Context) (state.ConnectStrings, error) {
	selector, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Operator: metav1.LabelSelectorOpExists,
			Key:      ZarfConnectLabelName,
		}},
	})
	if err != nil {
		return nil, err
	}
	serviceList, err := c.Clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, err
	}
	connections := state.ConnectStrings{}
	for _, svc := range serviceList.Items {
		name := svc.Labels[ZarfConnectLabelName]
		connections[name] = state.ConnectString{
			Description: svc.Annotations[ZarfConnectAnnotationDescription],
			URL:         svc.Annotations[ZarfConnectAnnotationURL],
		}
	}
	return connections, nil
}

// NewTargetTunnelInfo returns a new TunnelInfo object for the specified target.
func (c *Cluster) NewTargetTunnelInfo(ctx context.Context, target string) (TunnelInfo, error) {
	zt := TunnelInfo{
		Namespace:       state.ZarfNamespaceName,
		ResourceType:    SvcResource,
		ListenAddresses: []string{helpers.IPV4Localhost},
	}

	switch strings.ToUpper(target) {
	case ZarfRegistry:
		zt.ResourceName = ZarfRegistryName
		zt.RemotePort = ZarfRegistryPort
		zt.urlSuffix = `/v2/_catalog`
	case ZarfGit:
		zt.ResourceName = ZarfGitServerName
		zt.RemotePort = ZarfGitServerPort
	case ZarfInjector:
		zt.ResourceName = ZarfInjectorName
		zt.RemotePort = ZarfInjectorPort
	default:
		if target != "" {
			ztNew, err := c.checkForZarfConnectLabel(ctx, target)
			if err != nil {
				return TunnelInfo{}, fmt.Errorf("problem looking for a zarf connect label in the cluster: %s", err.Error())
			}
			zt = ztNew
			zt.ListenAddresses = []string{helpers.IPV4Localhost}
		}
		if zt.ResourceName == "" {
			return TunnelInfo{}, fmt.Errorf("missing resource name")
		}
		if zt.RemotePort < 1 {
			return TunnelInfo{}, fmt.Errorf("missing remote port")
		}
	}
	return zt, nil
}

// Connect will establish a tunnel to the specified target.
func (c *Cluster) Connect(ctx context.Context, target string) (*Tunnel, error) {
	zt, err := c.NewTargetTunnelInfo(ctx, target)
	if err != nil {
		return nil, err
	}
	return c.ConnectTunnelInfo(ctx, zt)
}

// ConnectTunnelInfo connects to the cluster with the provided TunnelInfo
func (c *Cluster) ConnectTunnelInfo(ctx context.Context, zt TunnelInfo) (*Tunnel, error) {
	tunnel, err := c.NewTunnel(zt.Namespace, zt.ResourceType, zt.ResourceName, zt.urlSuffix, zt.LocalPort, zt.RemotePort, WithListenAddress(zt.ListenAddresses))
	if err != nil {
		return nil, err
	}

	_, err = tunnel.Connect(ctx)
	if err != nil {
		return nil, err
	}

	return tunnel, nil
}

// ConnectToZarfRegistryEndpoint determines if a registry endpoint is in cluster, and if so opens a tunnel to connect to it
func (c *Cluster) ConnectToZarfRegistryEndpoint(ctx context.Context, registryInfo state.RegistryInfo) (string, *Tunnel, error) {
	registryEndpoint := registryInfo.Address

	var err error
	var tunnel *Tunnel
	if registryInfo.IsInternal() {
		// Establish a registry tunnel to send the images to the zarf registry
		if tunnel, err = c.NewTunnel(state.ZarfNamespaceName, SvcResource, ZarfRegistryName, "", 0, ZarfRegistryPort); err != nil {
			return "", tunnel, err
		}
	} else if dns.IsServiceURL(registryInfo.Address) {
		namespace, name, port, err := dns.ParseServiceURL(registryInfo.Address)
		if err != nil {
			return "", tunnel, err
		}
		tunnel, err = c.NewTunnel(namespace, SvcResource, name, "", 0, port)
		if err != nil {
			return "", tunnel, err
		}
	} else {
		serviceList, err := c.Clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return "", nil, err
		}
		svc, port, err := serviceInfoFromNodePortURL(serviceList.Items, registryInfo.Address)

		// If this is a service (no error getting svcInfo), create a port-forward tunnel to that resource
		if err == nil {
			if tunnel, err = c.NewTunnel(svc.Namespace, SvcResource, svc.Name, "", 0, port); err != nil {
				return "", tunnel, err
			}
		}
	}

	if tunnel != nil {
		_, err = tunnel.Connect(ctx)
		if err != nil {
			return "", tunnel, err
		}
		// there is no support currently for multiple registry endpoints - will use the default 127.0.0.1
		endpoints := tunnel.Endpoints()
		if len(endpoints) == 0 {
			return "", tunnel, fmt.Errorf("no endpoints found")
		}
		registryEndpoint = endpoints[0]
	}

	return registryEndpoint, tunnel, nil
}

// checkForZarfConnectLabel looks in the cluster for a connect name that matches the target
func (c *Cluster) checkForZarfConnectLabel(ctx context.Context, name string) (TunnelInfo, error) {
	var err error
	var zt TunnelInfo

	selector, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
		MatchLabels: map[string]string{
			ZarfConnectLabelName: name,
		},
	})
	if err != nil {
		return TunnelInfo{}, err
	}
	listOpts := metav1.ListOptions{LabelSelector: selector.String()}
	serviceList, err := c.Clientset.CoreV1().Services("").List(ctx, listOpts)
	if err != nil {
		return TunnelInfo{}, err
	}

	if len(serviceList.Items) > 0 {
		// If there is a match, use the first one as these are supposed to be unique.
		svc := serviceList.Items[0]

		// Reset based on the matched params.
		zt.ResourceType = SvcResource
		zt.ResourceName = svc.Name
		zt.Namespace = svc.Namespace
		// Only support a service with a single port.
		zt.RemotePort = svc.Spec.Ports[0].TargetPort.IntValue()
		// if targetPort == 0, look for Port (which is required)
		if zt.RemotePort == 0 {
			// TODO: Need a check for if container port is not found
			remotePort, err := c.findPodContainerPort(ctx, svc)
			if err != nil {
				return TunnelInfo{}, err
			}
			zt.RemotePort = remotePort
		}

		// Add the url suffix too.
		zt.urlSuffix = svc.Annotations[ZarfConnectAnnotationURL]

		logger.From(ctx).Debug("tunnel connection match",
			"namespace", svc.Namespace,
			"name", svc.Name,
			"remotePort", zt.RemotePort)
	} else {
		return zt, fmt.Errorf("no matching services found for %s", name)
	}

	return zt, nil
}

func (c *Cluster) findPodContainerPort(ctx context.Context, svc corev1.Service) (int, error) {
	selector, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: svc.Spec.Selector})
	if err != nil {
		return 0, err
	}
	podList, err := c.Clientset.CoreV1().Pods(svc.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return 0, err
	}
	for _, pod := range podList.Items {
		// Find the matching name on the port in the pod
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				if port.Name == svc.Spec.Ports[0].TargetPort.String() {
					return int(port.ContainerPort), nil
				}
			}
		}
	}
	return 0, nil
}

// TODO: Refactor to use netip.AddrPort instead of a string for nodePortURL.
func serviceInfoFromNodePortURL(services []corev1.Service, nodePortURL string) (corev1.Service, int, error) {
	// Attempt to parse as normal, if this fails add a scheme to the URL (docker registries don't use schemes)
	parsedURL, err := url.Parse(nodePortURL)
	if err != nil {
		parsedURL, err = url.Parse("scheme://" + nodePortURL)
		if err != nil {
			return corev1.Service{}, 0, err
		}
	}

	// Match hostname against localhost ip/hostnames
	hostname := parsedURL.Hostname()
	if hostname != helpers.IPV4Localhost && hostname != "localhost" {
		return corev1.Service{}, 0, fmt.Errorf("node port services should be on localhost")
	}

	// Get the node port from the nodeportURL.
	nodePort, err := strconv.Atoi(parsedURL.Port())
	if err != nil {
		return corev1.Service{}, 0, err
	}
	if nodePort < 30000 || nodePort > 32767 {
		return corev1.Service{}, 0, fmt.Errorf("node port services should use the port range 30000-32767")
	}

	for _, svc := range services {
		if svc.Spec.Type == "NodePort" {
			for _, port := range svc.Spec.Ports {
				if int(port.NodePort) == nodePort {
					return svc, int(port.Port), nil
				}
			}
		}
	}

	return corev1.Service{}, 0, fmt.Errorf("no matching node port services found")
}

// Global lock to synchronize port selections.
var globalMutex sync.Mutex

// Zarf Tunnel Configuration Constants.
const (
	PodResource = "pod"
	SvcResource = "svc"
)

// TunnelOption is a function that configures a tunnel
type TunnelOption func(*Tunnel)

// WithListenAddress will set the listen address for the tunnel
func WithListenAddress(addr []string) TunnelOption {
	return func(t *Tunnel) {
		t.listenAddress = addr
	}
}

// Tunnel is the main struct that configures and manages port forwarding tunnels to Kubernetes resources.
type Tunnel struct {
	clientset     kubernetes.Interface
	restConfig    *rest.Config
	localPort     int
	remotePort    int
	namespace     string
	resourceType  string
	resourceName  string
	urlSuffix     string
	listenAddress []string
	stopChan      chan struct{}
	readyChan     chan struct{}
	errChan       chan error
}

// NewTunnel will create a new Tunnel struct.
// Note that if you use 0 for the local port, an open port on the host system
// will be selected automatically, and the Tunnel struct will be updated with the selected port.
func (c *Cluster) NewTunnel(namespace, resourceType, resourceName, urlSuffix string, local, remote int, opts ...TunnelOption) (*Tunnel, error) {
	t := &Tunnel{
		clientset:    c.Clientset,
		restConfig:   c.RestConfig,
		localPort:    local,
		remotePort:   remote,
		namespace:    namespace,
		resourceType: resourceType,
		resourceName: resourceName,
		urlSuffix:    urlSuffix,
		listenAddress: []string{
			"127.0.0.1", // default
		},
		stopChan:  make(chan struct{}, 1),
		readyChan: make(chan struct{}, 1),
	}

	for _, opt := range opts {
		opt(t)
	}
	return t, nil
}

// Wrap takes a function that returns an error and wraps it to check for tunnel errors as well.
func (tunnel *Tunnel) Wrap(function func() error) error {
	var err error
	funcErrChan := make(chan error, 1)

	go func() {
		funcErrChan <- function()
	}()

	select {
	case err = <-funcErrChan:
		return err
	case err = <-tunnel.ErrChan():
		return err
	}
}

// Connect will establish a tunnel to the specified target.
func (tunnel *Tunnel) Connect(ctx context.Context) ([]string, error) {
	urls, err := retry.DoWithData(func() ([]string, error) {
		urls, err := tunnel.establish(ctx)
		if err != nil {
			return []string{}, err
		}
		return urls, nil
	}, retry.Context(ctx), retry.Attempts(6))
	if err != nil {
		return []string{}, err
	}
	return urls, nil
}

// Endpoints returns all tunnel endpoints
func (tunnel *Tunnel) Endpoints() []string {
	endpoints := make([]string, len(tunnel.listenAddress))
	for i, addr := range tunnel.listenAddress {
		endpoints[i] = fmt.Sprintf("%s:%d", addr, tunnel.localPort)
	}
	return endpoints
}

// ErrChan returns the tunnel's error channel
func (tunnel *Tunnel) ErrChan() chan error {
	return tunnel.errChan
}

// HTTPEndpoints returns all tunnel endpoints as a list of HTTP URL strings.
func (tunnel *Tunnel) HTTPEndpoints() []string {
	endpoints := tunnel.Endpoints()
	httpEndpoints := make([]string, len(endpoints))
	for i, addr := range endpoints {
		httpEndpoints[i] = fmt.Sprintf("http://%s", addr)
	}
	return httpEndpoints
}

// FullURLs returns the tunnel endpoint as a HTTP URL string with the urlSuffix appended.
func (tunnel *Tunnel) FullURLs() []string {
	endpoints := tunnel.HTTPEndpoints()
	fullEndpoints := make([]string, len(endpoints))
	for i, addr := range endpoints {
		fullEndpoints[i] = fmt.Sprintf("%s%s", addr, tunnel.urlSuffix)
	}
	return fullEndpoints
}

// Close disconnects a tunnel connection by closing the StopChan, thereby stopping the goroutine.
func (tunnel *Tunnel) Close() {
	if tunnel.stopChan == nil {
		return
	}
	select {
	case <-tunnel.stopChan:
	default:
		close(tunnel.stopChan)
	}
}

// establish opens a tunnel to a kubernetes resource, as specified by the provided tunnel struct.
func (tunnel *Tunnel) establish(ctx context.Context) ([]string, error) {
	var err error
	l := logger.From(ctx)

	// Track this locally as we may need to retry if the tunnel fails.
	localPort := tunnel.localPort

	// If the local-port is 0, get an available port before continuing. We do this here instead of relying on the
	// underlying port-forwarder library, because the port-forwarder library does not expose the selected local port in a
	// machine-readable manner.
	// Synchronize on the global lock to avoid race conditions with concurrently selecting the same available port,
	// since there is a brief moment between `GetAvailablePort` and `forwarder.ForwardPorts` where the selected port
	// is available for selection again.
	if localPort == 0 {
		l.Debug("requested local port is 0. Selecting an open port on host system")
		localPort, err = helpers.GetAvailablePort()
		if err != nil {
			return []string{}, fmt.Errorf("unable to find an available port: %w", err)
		}
		l.Debug("selected port", "port", localPort)
		globalMutex.Lock()
		defer globalMutex.Unlock()
	}

	l.Debug("opening tunnel",
		"localPort", localPort,
		"address", tunnel.listenAddress,
		"remotePort", tunnel.remotePort,
		"resourceType", tunnel.resourceType,
		"resourceName", tunnel.resourceName,
		"namespace", tunnel.namespace,
	)

	// Find the pod to port forward to
	podName, err := tunnel.getAttachablePodForResource(ctx)
	if err != nil {
		return []string{}, fmt.Errorf("unable to find pod attached to given resource: %w", err)
	}
	l.Debug("selected pod to open port forward to", "name", podName)

	// Build url to the port forward endpoint.
	// Example: http://localhost:8080/api/v1/namespaces/helm/pods/tiller-deploy-9itlq/portforward.
	postEndpoint := tunnel.clientset.CoreV1().RESTClient().Post()
	namespace := tunnel.namespace
	portForwardCreateURL := postEndpoint.
		Resource("pods").
		Namespace(namespace).
		Name(podName).
		SubResource("portforward").
		URL()

	l.Debug("using URL to create portforward", "url", portForwardCreateURL)

	dialer, err := createDialer(http.MethodPost, portForwardCreateURL, tunnel.restConfig)
	if err != nil {
		return []string{}, fmt.Errorf("unable to create the dialer %w", err)
	}

	// Construct a new PortForwarder struct that manages the instructed port forward tunnel.
	ports := []string{fmt.Sprintf("%d:%d", localPort, tunnel.remotePort)}
	portforwarder, err := portforward.NewOnAddresses(dialer, tunnel.listenAddress, ports, tunnel.stopChan, tunnel.readyChan, io.Discard, io.Discard)
	if err != nil {
		return []string{}, fmt.Errorf("unable to create the port forward: %w", err)
	}

	// Open the tunnel in a goroutine so that it is available in the background. Report errors to the main goroutine via
	// a new channel.
	errChan := make(chan error)
	go func() {
		errChan <- portforwarder.ForwardPorts()
	}()

	// Wait for an error or the tunnel to be ready.
	select {
	case err = <-errChan:
		return []string{}, fmt.Errorf("unable to start the tunnel: %w", err)
	case <-portforwarder.Ready:
		// Store for endpoint output
		tunnel.localPort = localPort
		urls := tunnel.FullURLs()
		if len(urls) == 0 {
			return []string{}, fmt.Errorf("no tunnel endpoints found")
		}

		// Store the error channel to listen for errors
		tunnel.errChan = errChan

		l.Debug("creating port forwarding tunnel", "urls", urls)
		return urls, nil
	}
}

// getAttachablePodForResource will find a pod that can be port forwarded to the provided resource type and return
// the name.
func (tunnel *Tunnel) getAttachablePodForResource(ctx context.Context) (string, error) {
	switch tunnel.resourceType {
	case PodResource:
		return tunnel.resourceName, nil
	case SvcResource:
		return tunnel.getAttachablePodForService(ctx)
	default:
		return "", fmt.Errorf("unknown resource type: %s", tunnel.resourceType)
	}
}

// getAttachablePodForService will find an active pod associated with the Service and return the pod name.
func (tunnel *Tunnel) getAttachablePodForService(ctx context.Context) (string, error) {
	service, err := tunnel.clientset.CoreV1().Services(tunnel.namespace).Get(ctx, tunnel.resourceName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("unable to find the service: %w", err)
	}
	selector, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: service.Spec.Selector})
	if err != nil {
		return "", err
	}
	listOpt := metav1.ListOptions{
		LabelSelector: selector.String(),
		FieldSelector: fmt.Sprintf("status.phase=%s", corev1.PodRunning),
	}
	podList, err := tunnel.clientset.CoreV1().Pods(tunnel.namespace).List(ctx, listOpt)
	if err != nil {
		return "", err
	}
	if len(podList.Items) < 1 {
		return "", fmt.Errorf("no pods found for service %s", tunnel.resourceName)
	}
	return podList.Items[0].Name, nil
}

// Inspired by https://github.com/kubernetes/kubernetes/blob/680ea07dbb2c6050d13b93660fa4d27d2d28d6eb/staging/src/k8s.io/kubectl/pkg/cmd/portforward/portforward.go#L139-L156
func createDialer(method string, url *url.URL, config *rest.Config) (httpstream.Dialer, error) {
	transport, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return nil, err
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, method, url)
	tunnelingDialer, err := portforward.NewSPDYOverWebsocketDialer(url, config)
	if err != nil {
		return nil, err
	}
	// First attempt tunneling (websocket) dialer, then fallback to spdy dialer.
	dialer = portforward.NewFallbackDialer(tunnelingDialer, dialer, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	return dialer, nil
}
