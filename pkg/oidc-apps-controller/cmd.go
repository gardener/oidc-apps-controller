// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package oidcappscontroller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gardenextensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	istioclientnetv1 "istio.io/client-go/pkg/apis/networking/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	autoscalerv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/scale/scheme/autoscalingv1"
	"k8s.io/utils/ptr"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	crhealthz "sigs.k8s.io/controller-runtime/pkg/healthz"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gardener/oidc-apps-controller/pkg/certificates"
	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/controllers"
	"github.com/gardener/oidc-apps-controller/pkg/healthz"
	"github.com/gardener/oidc-apps-controller/pkg/notifiers"
	oidcappswebhook "github.com/gardener/oidc-apps-controller/pkg/webhook"
)

var (
	extensionConfig *configuration.OIDCAppsControllerConfig
	predicates      predicate.GenerationChangedPredicate
	once            sync.Once
	_log            = logf.Log
)

// RunController is the entry point for initialzing and starting the controller-runtime manager
func RunController(ctx context.Context, o *Options) error {
	printGardenEnvVars()

	// Load extension configuration first to determine HTTPRoute support
	extensionConfig = configuration.CreateControllerConfigOrDie(o.controllerConfigPath)
	httpRouteEnabled := extensionConfig.IsHTTPRouteEnabled()
	istioGatewayEnabled := extensionConfig.IsIstioGatewayEnabled()

	if httpRouteEnabled {
		_log.Info("Gateway API HTTPRoute support enabled via configuration")
	}

	if istioGatewayEnabled {
		_log.Info("Istio Gateway support enabled via configuration")
	}

	// Initialize a scheme which will contain the API definitions
	sch := scheme.Scheme

	// Add core Kubernetes schemes
	if err := scheme.AddToScheme(sch); err != nil {
		return fmt.Errorf("could not initialize the runtime scheme: %w", err)
	}

	// Add autoscaler schemes
	if err := autoscalerv1.AddToScheme(sch); err != nil {
		return fmt.Errorf("could not initialize the runtime scheme: %w", err)
	}

	// Add Gateway API schemes for HTTPRoute support (only when enabled in config)
	if httpRouteEnabled {
		if err := gatewayv1.Install(sch); err != nil {
			return fmt.Errorf("could not initialize the gateway-api scheme: %w", err)
		}
	}

	// Add Istio networking schemes for Istio Gateway support (only when enabled in config)
	if istioGatewayEnabled {
		if err := istioclientnetv1.AddToScheme(sch); err != nil {
			return fmt.Errorf("could not initialize the istio networking scheme: %w", err)
		}
	}

	// Limit the cache
	oidcAppsSelector := labels.Everything()

	if len(o.cacheSelectorString) > 0 {
		var err error
		if oidcAppsSelector, err = labels.Parse(o.cacheSelectorString); err != nil {
			return fmt.Errorf("could not parse the cache selector: %w", err)
		}

		_log.Info("Using cache selector", "selector", oidcAppsSelector.String())
	}

	cacheOptions := cache.Options{
		Scheme: sch,
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}: {
				Label: oidcAppsSelector,
			},
			&corev1.Secret{}: {
				Label: labels.SelectorFromSet(labels.Set{constants.LabelKey: constants.LabelValue}),
			},
			&corev1.Service{}: {
				Label: labels.SelectorFromSet(labels.Set{constants.LabelKey: constants.LabelValue}),
			},
			&corev1.Namespace{}: {},
			&networkingv1.Ingress{}: {
				Label: labels.SelectorFromSet(labels.Set{constants.LabelKey: constants.LabelValue}),
			},
			&autoscalerv1.VerticalPodAutoscaler{}: {
				Label: oidcAppsSelector,
			},
		}}

	// Add HTTPRoute to cache only when Gateway API support is enabled in config
	if httpRouteEnabled {
		cacheOptions.ByObject[&gatewayv1.HTTPRoute{}] = cache.ByObject{
			Label: labels.SelectorFromSet(labels.Set{constants.LabelKey: constants.LabelValue}),
		}
	}

	// Add Istio resources to cache only when Istio Gateway support is enabled in config
	if istioGatewayEnabled {
		cacheOptions.ByObject[&istioclientnetv1.VirtualService{}] = cache.ByObject{
			Label: labels.SelectorFromSet(labels.Set{constants.LabelKey: constants.LabelValue}),
		}
		cacheOptions.ByObject[&istioclientnetv1.Gateway{}] = cache.ByObject{
			Label: labels.SelectorFromSet(labels.Set{constants.LabelKey: constants.LabelValue}),
		}
		cacheOptions.ByObject[&istioclientnetv1.DestinationRule{}] = cache.ByObject{
			Label: labels.SelectorFromSet(labels.Set{constants.LabelKey: constants.LabelValue}),
		}
	}

	// Add additional scheme in case of running in gardener cluster
	if len(os.Getenv(constants.GardenKubeconfig)) > 0 {
		// Add gardener Cluster schemes
		if err := gardenextensionsv1alpha1.AddToScheme(sch); err != nil {
			return fmt.Errorf("could not initialize the runtime scheme: %w", err)
		}

		cluster := &gardenextensionsv1alpha1.Cluster{}
		cacheOptions.ByObject[cluster] = cache.ByObject{}
	}

	// NAMESPACE is a required environment variable for the oidc-apps-controller certificate manager
	if !o.useExternalCertManager && os.Getenv(constants.NAMESPACE) == "" {
		return errors.New("NAMESPACE environment variable is not set")
	}
	// NAMESPACE is a required environment variable for the image pull secret reconciler
	if o.registrySecret != "" && os.Getenv(constants.NAMESPACE) == "" {
		return errors.New("NAMESPACE environment variable is not set")
	}

	cfg := config.GetConfigOrDie()
	cfg.QPS = float32(100)
	cfg.Burst = 200

	mgr, err := manager.New(cfg,
		manager.Options{
			Cache:                         cacheOptions,
			Scheme:                        sch,
			LeaderElection:                true,
			LeaderElectionID:              "oidc-apps-controller",
			LeaderElectionNamespace:       os.Getenv(constants.NAMESPACE),
			LeaseDuration:                 ptr.To(15 * time.Second),
			RenewDeadline:                 ptr.To(10 * time.Second),
			RetryPeriod:                   ptr.To(2 * time.Second),
			LeaderElectionReleaseOnCancel: true,
			HealthProbeBindAddress:        ":8081",
			Metrics:                       metricsserver.Options{BindAddress: fmt.Sprintf(":%d", o.metricsPort)},
		},
	)
	if err != nil {
		return fmt.Errorf("could not initialize the controller-runtime manager: %w", err)
	}

	// Set domain name if we are running in a gardener cluster
	if len(os.Getenv(constants.GardenKubeconfig)) > 0 && os.Getenv(constants.GardenSeedDomainName) == "" {
		if err := setGardenDomainNameEnvVar(ctx, mgr.GetConfig()); err != nil {
			return fmt.Errorf("could not set the garden domain name: %w", err)
		}
	}

	// Update extension config with client and logger now that manager is ready
	extensionConfig.SetClient(mgr.GetClient())
	extensionConfig.SetLogger(mgr.GetLogger())

	if err := initializeManagerIndices(mgr); err != nil {
		return fmt.Errorf("could not initialize cache indices: %w", err)
	}

	if err := addDeploymentController(mgr); err != nil {
		return fmt.Errorf("could not initialize deployment controller: %w", err)
	}

	if err := addStatefulSetController(mgr); err != nil {
		return fmt.Errorf("could not initialize statefulset controller: %w", err)
	}

	if err := addWebhookCertificateManager(mgr, o); err != nil {
		return fmt.Errorf("could not initialize webhook certificate manager: %w", err)
	}

	if err := addGardenAccessTokenNotifier(mgr); err != nil {
		return fmt.Errorf("could not initialize gardener access token manager: %w", err)
	}

	if err := addPrivateRegistrySecretControllers(mgr, o); err != nil {
		return fmt.Errorf("could not initialize private registry secret manager: %w", err)
	}

	if err := addWebhooks(mgr, o); err != nil {
		return fmt.Errorf("could not initialize mutating webhooks: %w", err)
	}

	if err := mgr.AddReadyzCheck("informer-sync", healthz.NewCacheSyncHealthz(mgr.GetCache())); err != nil {
		return fmt.Errorf("could not initialize controller readycheck: %w", err)
	}

	if err := mgr.AddHealthzCheck("ping", crhealthz.Ping); err != nil {
		return fmt.Errorf("could not initialize controller healthcheck: %w", err)
	}

	// Start the manager
	return mgr.Start(ctx)
}

func printGardenEnvVars() {
	for _, v := range os.Environ() {
		if strings.HasPrefix(v, "GARDEN") {
			_log.Info(fmt.Sprintf("ENV: %s", v))
		}
	}
}

func setGardenDomainNameEnvVar(ctx context.Context, cfg *rest.Config) error {
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		return fmt.Errorf("could not initialize the controller-runtime client: %w", err)
	}

	if host := discoverDomainFromIngress(ctx, c); host != "" {
		return setDomainEnv(host)
	}

	if host := discoverDomainFromIstioVirtualService(ctx, c); host != "" {
		return setDomainEnv(host)
	}

	// not attempting to discover through an HTTPRoute, as the gardener project
	// has no such implementation in place

	return fmt.Errorf("could not discover seed domain: no kube-apiserver Ingress, VirtualService, or HTTPRoute found in garden namespace")
}

func setDomainEnv(domain string) error {
	if err := os.Setenv(constants.GardenSeedDomainName, domain); err != nil {
		return fmt.Errorf("could not set the garden domain name: %w", err)
	}

	_log.Info("Set domain name env variable", constants.GardenSeedDomainName, domain)

	return nil
}

const kubeApiserverHostPrefix = "api-seed."

func discoverDomainFromIngress(ctx context.Context, c client.Client) string {
	ingress := &networkingv1.Ingress{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "garden", Name: "kube-apiserver"}, ingress); err != nil {
		return ""
	}

	if len(ingress.Spec.Rules) > 0 {
		return stripAPIPrefix(ingress.Spec.Rules[0].Host)
	}

	return ""
}

func discoverDomainFromIstioVirtualService(ctx context.Context, c client.Client) string {
	vs := &istioclientnetv1.VirtualService{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "garden", Name: "kube-apiserver"}, vs); err != nil {
		return ""
	}

	if len(vs.Spec.Hosts) > 0 {
		return stripAPIPrefix(vs.Spec.Hosts[0])
	}

	return ""
}

// stripAPIPrefix extracts the seed domain from a kube-apiserver host.
// If the host has the expected "api-seed." prefix, it is stripped.
// Otherwise the host is returned as-is.
func stripAPIPrefix(host string) string {
	return strings.TrimPrefix(host, kubeApiserverHostPrefix)
}

func fetchPredicates(extensionConfig *configuration.OIDCAppsControllerConfig) predicate.GenerationChangedPredicate {
	once.Do(
		func() {
			predicates = predicate.GenerationChangedPredicate{

				TypedFuncs: predicate.Funcs{
					CreateFunc: func(e event.CreateEvent) bool {
						if extensionConfig.Match(e.Object) {
							_log.V(9).Info("create event", "name", e.Object.GetName(), "namespace", e.Object.GetNamespace())

							return true
						}

						_, found := e.Object.GetLabels()[constants.LabelKey]

						return found
					},
					DeleteFunc: func(e event.DeleteEvent) bool {
						if extensionConfig.Match(e.Object) {
							_log.V(9).Info("delete event", "name", e.Object.GetName(), "namespace",
								e.Object.GetNamespace())

							return true
						}

						_, found := e.Object.GetLabels()[constants.LabelKey]

						return found
					},
					UpdateFunc: func(e event.UpdateEvent) bool {
						if extensionConfig.Match(e.ObjectNew) {
							_log.V(9).Info("update event", "name", e.ObjectNew.GetName(), "namespace",
								e.ObjectNew.GetNamespace())

							return true
						}

						_, found := e.ObjectNew.GetLabels()[constants.LabelKey]

						return found
					},
					GenericFunc: func(e event.GenericEvent) bool {
						if extensionConfig.Match(e.Object) {
							_log.V(9).Info("generic event", "name", e.Object.GetName(), "namespace",
								e.Object.GetNamespace())

							return true
						}

						_, found := e.Object.GetLabels()[constants.LabelKey]

						return found
					},
				},
			}
		},
	)

	return predicates
}

func initializeManagerIndices(mgr manager.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&corev1.Secret{},
		"metadata.labels"+constants.LabelKey,
		func(obj client.Object) []string {
			secret, ok := obj.(*corev1.Secret)
			if !ok {
				_log.Error(errors.New("object is not a secret"), "object", obj)

				return nil
			}

			if value, exists := secret.GetLabels()[constants.LabelKey]; exists {
				return []string{value}
			}

			return nil
		},
	); err != nil {
		return fmt.Errorf("could not set up the oidc-app-controller %T index: %w", corev1.Secret{}, err)
	}

	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&corev1.Service{},
		"metadata.labels"+constants.LabelKey,
		func(obj client.Object) []string {
			service, ok := obj.(*corev1.Service)
			if !ok {
				_log.Error(errors.New("object is not a service"), "object", obj)

				return nil
			}

			if value, exists := service.GetLabels()[constants.LabelKey]; exists {
				return []string{value}
			}

			return nil
		},
	); err != nil {
		return fmt.Errorf("could not set up the oidc-app-controller %T index: %w", corev1.Service{}, err)
	}

	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&networkingv1.Ingress{},
		"metadata.labels"+constants.LabelKey,
		func(obj client.Object) []string {
			ingress, ok := obj.(*networkingv1.Ingress)
			if !ok {
				_log.Error(errors.New("object is not an ingress"), "object", obj)

				return nil
			}

			if value, exists := ingress.GetLabels()[constants.LabelKey]; exists {
				return []string{value}
			}

			return nil
		},
	); err != nil {
		return fmt.Errorf("could not set up the oidc-app-controller %T index: %w", networkingv1.Ingress{}, err)
	}

	// Add HTTPRoute index only when Gateway API support is enabled
	if extensionConfig.IsHTTPRouteEnabled() {
		if err := mgr.GetFieldIndexer().IndexField(
			context.Background(),
			&gatewayv1.HTTPRoute{},
			"metadata.labels"+constants.LabelKey,
			func(obj client.Object) []string {
				httpRoute, ok := obj.(*gatewayv1.HTTPRoute)
				if !ok {
					_log.Error(errors.New("object is not an httproute"), "object", obj)

					return nil
				}

				if value, exists := httpRoute.GetLabels()[constants.LabelKey]; exists {
					return []string{value}
				}

				return nil
			},
		); err != nil {
			return fmt.Errorf("could not set up the oidc-app-controller %T index: %w", gatewayv1.HTTPRoute{}, err)
		}
	}

	// Add Istio resource index only when Istio Gateway support is enabled
	if extensionConfig.IsIstioGatewayEnabled() {
		if err := mgr.GetFieldIndexer().IndexField(
			context.Background(),
			&istioclientnetv1.VirtualService{},
			"metadata.labels"+constants.LabelKey,
			func(obj client.Object) []string {
				vs, ok := obj.(*istioclientnetv1.VirtualService)
				if !ok {
					_log.Error(errors.New("object is not a virtualservice"), "object", obj)

					return nil
				}

				if value, exists := vs.GetLabels()[constants.LabelKey]; exists {
					return []string{value}
				}

				return nil
			},
		); err != nil {
			return fmt.Errorf("could not set up the oidc-app-controller %T index: %w", istioclientnetv1.VirtualService{}, err)
		}

		if err := mgr.GetFieldIndexer().IndexField(
			context.Background(),
			&istioclientnetv1.Gateway{},
			"metadata.labels"+constants.LabelKey,
			func(obj client.Object) []string {
				gw, ok := obj.(*istioclientnetv1.Gateway)
				if !ok {
					_log.Error(errors.New("object is not a gateway"), "object", obj)

					return nil
				}

				if value, exists := gw.GetLabels()[constants.LabelKey]; exists {
					return []string{value}
				}

				return nil
			},
		); err != nil {
			return fmt.Errorf("could not set up the oidc-app-controller %T index: %w", istioclientnetv1.Gateway{}, err)
		}
	}

	return nil
}

func addDeploymentController(mgr manager.Manager) error {
	controllerBuilder := controllerruntime.NewControllerManagedBy(mgr).
		Named("oidc-apps-deployments").
		For(&appsv1.Deployment{}).
		WithEventFilter(fetchPredicates(extensionConfig)).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(),
				mgr.GetRESTMapper(),
				&appsv1.Deployment{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(),
				mgr.GetRESTMapper(),
				&appsv1.Deployment{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&networkingv1.Ingress{},
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(),
				mgr.GetRESTMapper(),
				&appsv1.Deployment{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(PodMapFuncForDeployment(mgr)),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}))

	// Add HTTPRoute watches only when Gateway API support is enabled
	if extensionConfig.IsHTTPRouteEnabled() {
		controllerBuilder = controllerBuilder.Watches(
			&gatewayv1.HTTPRoute{},
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(),
				mgr.GetRESTMapper(),
				&appsv1.Deployment{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}))
	}

	// Add Istio resource watches only when Istio Gateway support is enabled
	if extensionConfig.IsIstioGatewayEnabled() {
		controllerBuilder = controllerBuilder.Watches(
			&istioclientnetv1.VirtualService{},
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(),
				mgr.GetRESTMapper(),
				&appsv1.Deployment{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}))
		controllerBuilder = controllerBuilder.Watches(
			&istioclientnetv1.Gateway{},
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(),
				mgr.GetRESTMapper(),
				&appsv1.Deployment{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}))
		controllerBuilder = controllerBuilder.Watches(
			&istioclientnetv1.DestinationRule{},
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(),
				mgr.GetRESTMapper(),
				&appsv1.Deployment{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}))
	}

	return controllerBuilder.Complete(&controllers.DeploymentReconciler{Client: mgr.GetClient()})
}

func addStatefulSetController(mgr manager.Manager) error {
	controllerBuilder := controllerruntime.NewControllerManagedBy(mgr).
		Named("oidc-apps-statefulsets").
		For(&appsv1.StatefulSet{}).
		WithEventFilter(fetchPredicates(extensionConfig)).
		Watches(
			&corev1.Pod{},
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(),
				mgr.GetRESTMapper(),
				&appsv1.StatefulSet{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(),
				mgr.GetRESTMapper(),
				&appsv1.StatefulSet{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(ServiceMapFuncForStatefulset(mgr)),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&networkingv1.Ingress{},
			handler.EnqueueRequestsFromMapFunc(IngressMapFuncForStatefulset(mgr)),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}))

	// Add HTTPRoute watches only when Gateway API support is enabled
	if extensionConfig.IsHTTPRouteEnabled() {
		controllerBuilder = controllerBuilder.Watches(
			&gatewayv1.HTTPRoute{},
			handler.EnqueueRequestsFromMapFunc(HTTPRouteMapFuncForStatefulset(mgr)),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}))
	}

	// Add Istio resource watches only when Istio Gateway support is enabled
	if extensionConfig.IsIstioGatewayEnabled() {
		controllerBuilder = controllerBuilder.Watches(
			&istioclientnetv1.VirtualService{},
			handler.EnqueueRequestsFromMapFunc(VirtualServiceMapFuncForStatefulset(mgr)),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}))
		controllerBuilder = controllerBuilder.Watches(
			&istioclientnetv1.Gateway{},
			handler.EnqueueRequestsFromMapFunc(GatewayMapFuncForStatefulset(mgr)),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}))
		controllerBuilder = controllerBuilder.Watches(
			&istioclientnetv1.DestinationRule{},
			handler.EnqueueRequestsFromMapFunc(DestinationRuleMapFuncForStatefulset(mgr)),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}))
	}

	return controllerBuilder.Complete(&controllers.StatefulSetReconciler{Client: mgr.GetClient()})
}

// Add certificate manager in case no external certificate manager is available
func addWebhookCertificateManager(mgr manager.Manager, o *Options) error {
	if !o.useExternalCertManager {
		certManager, err := certificates.New(o.webhookCertsDir, o.webhookName, os.Getenv(constants.NAMESPACE), mgr.GetClient(), mgr.GetConfig())
		if err != nil {
			return err
		}

		return mgr.Add(certManager)
	}

	return nil
}

func addGardenAccessTokenNotifier(mgr manager.Manager) error {
	// Add garden-secret-notifier if the GARDEN environment variables are present
	if os.Getenv(constants.GardenKubeconfig) != "" || os.Getenv(constants.GardenAccessToken) != "" {
		kubeconfigPath := filepath.Dir(os.Getenv(constants.GardenKubeconfig))

		tokenPath := os.Getenv(constants.GardenAccessToken)
		if tokenPath == "" {
			tokenPath = filepath.Dir(os.Getenv(constants.GardenKubeconfig))
		}

		accessTokenNotifier := notifiers.NewGardenerAccessTokenNotifier(
			mgr.GetClient(),
			filepath.Join(kubeconfigPath, "kubeconfig"),
			filepath.Join(tokenPath, "token"),
		)

		return mgr.Add(accessTokenNotifier)
	}

	return nil
}

// Add namespace && image pull secret reconcilers if the registry-secret parameter is present
func addPrivateRegistrySecretControllers(mgr manager.Manager, o *Options) error {
	if o.registrySecret != "" {
		imagePullSecretPredicates := predicate.GenerationChangedPredicate{
			TypedFuncs: predicate.Funcs{
				CreateFunc: func(e event.CreateEvent) bool {
					return e.Object.GetName() == o.registrySecret && e.Object.GetNamespace() == os.Getenv(constants.NAMESPACE)
				},
				UpdateFunc: func(e event.UpdateEvent) bool {
					return e.ObjectNew.GetName() == o.registrySecret && e.ObjectNew.GetNamespace() == os.Getenv(constants.NAMESPACE)
				},
				DeleteFunc: func(e event.DeleteEvent) bool {
					return e.Object.GetName() == o.registrySecret && e.Object.GetNamespace() == os.Getenv(constants.NAMESPACE)
				},
				GenericFunc: func(e event.GenericEvent) bool {
					return e.Object.GetName() == o.registrySecret && e.Object.GetNamespace() == os.Getenv(constants.NAMESPACE)
				},
			},
		}
		if err := controllerruntime.NewControllerManagedBy(mgr).
			Named("image-pull-secret").
			For(&corev1.Secret{}).
			WithEventFilter(imagePullSecretPredicates).
			Complete(&controllers.ImagePullSecretReconciler{Client: mgr.GetClient(),
				SecretName: o.registrySecret}); err != nil {
			return err
		}

		secretKey := types.NamespacedName{
			Namespace: os.Getenv(constants.NAMESPACE),
			Name:      o.registrySecret,
		}

		if err := controllerruntime.NewControllerManagedBy(mgr).
			Named("namespace").
			For(&corev1.Namespace{}).
			Complete(&controllers.NamespaceReconciler{Client: mgr.GetClient(), Secret: secretKey}); err != nil {
			return err
		}
	}

	return nil
}

func addWebhooks(mgr manager.Manager, o *Options) error {
	// Add Mutating Admission Webhook Server
	webhookServer := webhook.NewServer(webhook.Options{
		Port:    o.webhookPort,
		CertDir: o.webhookCertsDir,
	})

	webhookServer.Register(
		constants.PodWebHookPath,
		&webhook.Admission{Handler: &oidcappswebhook.PodMutator{
			Client:          mgr.GetClient(),
			Decoder:         admission.NewDecoder(scheme.Scheme),
			ImagePullSecret: o.registrySecret,
		}},
	)

	s := runtime.NewScheme()
	if err := autoscalingv1.AddToScheme(s); err != nil {
		return err
	}

	webhookServer.Register(
		constants.VpaWebHookPath,
		&webhook.Admission{Handler: &oidcappswebhook.VPAMutator{
			Client:  mgr.GetClient(),
			Decoder: admission.NewDecoder(s),
		}},
	)

	// Add the server to the manager
	return mgr.Add(webhookServer)
}

// IsOidcAppsPod returns true if the pod is an oidc-apps enabled pod
func IsOidcAppsPod(pod *corev1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name == constants.ContainerNameOauth2Proxy || c.Name == constants.ContainerNameKubeRbacProxy {
			_log.V(9).Info("oidc-apps enabled pod", "pod", pod.Name)

			return true
		}
	}

	return false
}

// PodMapFuncForDeployment returns a map function that returns reconcile requests for a target deployment triggered
// on changes of the owned pods
func PodMapFuncForDeployment(mgr manager.Manager) func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			_log.Error(errors.New("object is not a pod"), "object", obj)

			return nil
		}

		if !IsOidcAppsPod(pod) {
			return nil
		}

		c := mgr.GetClient()

		for _, r := range pod.GetOwnerReferences() {
			if r.Kind != "ReplicaSet" {
				continue
			}

			rs := &appsv1.ReplicaSet{}
			if err := c.Get(ctx, types.NamespacedName{Name: r.Name, Namespace: pod.Namespace}, rs); client.IgnoreNotFound(err) != nil {
				_log.Error(err, "could not get replicaset", "name", r.Name, "namespace", pod.Namespace)
			}

			for _, d := range rs.GetOwnerReferences() {
				if d.Kind != "Deployment" {
					continue
				}

				deployment := &appsv1.Deployment{}
				if err := c.Get(ctx, types.NamespacedName{Name: d.Name, Namespace: rs.Namespace}, deployment); client.IgnoreNotFound(err) != nil {
					_log.Error(err, "could not get deployment", "name", d.Name, "namespace", rs.Namespace)
				}

				_log.V(9).Info("enqueue deployment", "name", deployment.Name, "namespace", deployment.Namespace)

				return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}}}
			}
		}

		return nil
	}
}

// IngressMapFuncForStatefulset returns a map function that returns reconcile requests for a target statefulset triggered
// on changes of an ingress owned by a pod owned by the statefulset
func IngressMapFuncForStatefulset(mgr manager.Manager) func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		ingress, ok := obj.(*networkingv1.Ingress)
		if !ok {
			_log.Error(errors.New("object is not an ingress"), "object", obj)

			return nil
		}

		c := mgr.GetClient()

		for _, o := range ingress.GetOwnerReferences() {
			if o.Kind != "Pod" {
				continue
			}

			pod := &corev1.Pod{}
			if err := c.Get(ctx, types.NamespacedName{Name: o.Name, Namespace: ingress.Namespace}, pod); client.IgnoreNotFound(err) != nil {
				_log.Error(err, "could not get pod", "name", o.Name, "namespace", ingress.Namespace)
			}

			if len(pod.Name) == 0 {
				continue
			}

			for _, r := range pod.GetOwnerReferences() {
				if r.Kind != "StatefulSet" {
					continue
				}

				statefulset := &appsv1.StatefulSet{}
				if err := c.Get(ctx, types.NamespacedName{Name: r.Name, Namespace: pod.Namespace}, statefulset); client.IgnoreNotFound(err) != nil {
					_log.Error(err, "could not get statefulset", "name", r.Name, "namespace", pod.Namespace)
				}

				_log.V(9).Info("enqueue statefulset", "name", statefulset.Name, "namespace",
					statefulset.Namespace)

				return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: statefulset.Name, Namespace: statefulset.Namespace}}}
			}
		}

		return nil
	}
}

// ServiceMapFuncForStatefulset returns a map function that returns reconcile requests for a target statefulset triggered
// on changes of a service owned by a pod owned by the statefulset
func ServiceMapFuncForStatefulset(mgr manager.Manager) func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		service, ok := obj.(*corev1.Service)
		if !ok {
			_log.Error(errors.New("object is not a service"), "object", obj)

			return nil
		}

		c := mgr.GetClient()

		for _, o := range service.GetOwnerReferences() {
			if o.Kind != "Pod" {
				continue
			}

			pod := &corev1.Pod{}
			if err := c.Get(ctx, types.NamespacedName{Name: o.Name, Namespace: service.Namespace}, pod); client.IgnoreNotFound(err) != nil {
				_log.Error(err, "could not get pod", "name", o.Name, "namespace", service.Namespace)
			}

			if len(pod.Name) == 0 {
				continue
			}

			for _, r := range pod.GetOwnerReferences() {
				if r.Kind != "StatefulSet" {
					continue
				}

				statefulset := &appsv1.StatefulSet{}
				if err := c.Get(ctx, types.NamespacedName{Name: r.Name, Namespace: pod.Namespace}, statefulset); client.IgnoreNotFound(err) != nil {
					_log.Error(err, "could not get statefulset", "name", r.Name, "namespace", pod.Namespace)
				}

				_log.V(9).Info("enqueue statefulset", "name", statefulset.Name, "namespace", statefulset.Namespace)

				return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: statefulset.Name, Namespace: statefulset.Namespace}}}
			}
		}

		return nil
	}
}

// HTTPRouteMapFuncForStatefulset returns a map function that returns reconcile requests for a target statefulset triggered
// on changes of an HTTPRoute owned by a pod owned by the statefulset
func HTTPRouteMapFuncForStatefulset(mgr manager.Manager) func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		httpRoute, ok := obj.(*gatewayv1.HTTPRoute)
		if !ok {
			_log.Error(errors.New("object is not an httproute"), "object", obj)

			return nil
		}

		c := mgr.GetClient()

		for _, o := range httpRoute.GetOwnerReferences() {
			if o.Kind != "Pod" {
				continue
			}

			pod := &corev1.Pod{}
			if err := c.Get(ctx, types.NamespacedName{Name: o.Name, Namespace: httpRoute.Namespace}, pod); client.IgnoreNotFound(err) != nil {
				_log.Error(err, "could not get pod", "name", o.Name, "namespace", httpRoute.Namespace)
			}

			if len(pod.Name) == 0 {
				continue
			}

			for _, r := range pod.GetOwnerReferences() {
				if r.Kind != "StatefulSet" {
					continue
				}

				statefulset := &appsv1.StatefulSet{}
				if err := c.Get(ctx, types.NamespacedName{Name: r.Name, Namespace: pod.Namespace}, statefulset); client.IgnoreNotFound(err) != nil {
					_log.Error(err, "could not get statefulset", "name", r.Name, "namespace", pod.Namespace)
				}

				_log.V(9).Info("enqueue statefulset", "name", statefulset.Name, "namespace", statefulset.Namespace)

				return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: statefulset.Name, Namespace: statefulset.Namespace}}}
			}
		}

		return nil
	}
}

// VirtualServiceMapFuncForStatefulset returns a map function that returns reconcile requests for a target statefulset triggered
// on changes of a VirtualService owned by a pod owned by the statefulset
func VirtualServiceMapFuncForStatefulset(mgr manager.Manager) func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		vs, ok := obj.(*istioclientnetv1.VirtualService)
		if !ok {
			_log.Error(errors.New("object is not a virtualservice"), "object", obj)

			return nil
		}

		c := mgr.GetClient()

		for _, o := range vs.GetOwnerReferences() {
			if o.Kind != "Pod" {
				continue
			}

			pod := &corev1.Pod{}
			if err := c.Get(ctx, types.NamespacedName{Name: o.Name, Namespace: vs.Namespace}, pod); client.IgnoreNotFound(err) != nil {
				_log.Error(err, "could not get pod", "name", o.Name, "namespace", vs.Namespace)
			}

			if len(pod.Name) == 0 {
				continue
			}

			for _, r := range pod.GetOwnerReferences() {
				if r.Kind != "StatefulSet" {
					continue
				}

				statefulset := &appsv1.StatefulSet{}
				if err := c.Get(ctx, types.NamespacedName{Name: r.Name, Namespace: pod.Namespace}, statefulset); client.IgnoreNotFound(err) != nil {
					_log.Error(err, "could not get statefulset", "name", r.Name, "namespace", pod.Namespace)
				}

				_log.V(9).Info("enqueue statefulset", "name", statefulset.Name, "namespace", statefulset.Namespace)

				return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: statefulset.Name, Namespace: statefulset.Namespace}}}
			}
		}

		return nil
	}
}

// GatewayMapFuncForStatefulset returns a map function that returns reconcile requests for a target statefulset triggered
// on changes of a Gateway owned by a pod owned by the statefulset
func GatewayMapFuncForStatefulset(mgr manager.Manager) func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		gw, ok := obj.(*istioclientnetv1.Gateway)
		if !ok {
			_log.Error(errors.New("object is not a gateway"), "object", obj)

			return nil
		}

		c := mgr.GetClient()

		for _, o := range gw.GetOwnerReferences() {
			if o.Kind != "Pod" {
				continue
			}

			pod := &corev1.Pod{}
			if err := c.Get(ctx, types.NamespacedName{Name: o.Name, Namespace: gw.Namespace}, pod); client.IgnoreNotFound(err) != nil {
				_log.Error(err, "could not get pod", "name", o.Name, "namespace", gw.Namespace)
			}

			if len(pod.Name) == 0 {
				continue
			}

			for _, r := range pod.GetOwnerReferences() {
				if r.Kind != "StatefulSet" {
					continue
				}

				statefulset := &appsv1.StatefulSet{}
				if err := c.Get(ctx, types.NamespacedName{Name: r.Name, Namespace: pod.Namespace}, statefulset); client.IgnoreNotFound(err) != nil {
					_log.Error(err, "could not get statefulset", "name", r.Name, "namespace", pod.Namespace)
				}

				_log.V(9).Info("enqueue statefulset", "name", statefulset.Name, "namespace", statefulset.Namespace)

				return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: statefulset.Name, Namespace: statefulset.Namespace}}}
			}
		}

		return nil
	}
}

// DestinationRuleMapFuncForStatefulset returns a map function that returns reconcile requests for a target statefulset triggered
// on changes of a DestinationRule owned by a pod owned by the statefulset
func DestinationRuleMapFuncForStatefulset(mgr manager.Manager) func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		dr, ok := obj.(*istioclientnetv1.DestinationRule)
		if !ok {
			_log.Error(errors.New("object is not a destination rule"), "object", obj)

			return nil
		}

		c := mgr.GetClient()

		for _, o := range dr.GetOwnerReferences() {
			if o.Kind != "Pod" {
				continue
			}

			pod := &corev1.Pod{}
			if err := c.Get(ctx, types.NamespacedName{Name: o.Name, Namespace: dr.Namespace}, pod); client.IgnoreNotFound(err) != nil {
				_log.Error(err, "could not get pod", "name", o.Name, "namespace", dr.Namespace)
			}

			if len(pod.Name) == 0 {
				continue
			}

			for _, r := range pod.GetOwnerReferences() {
				if r.Kind != "StatefulSet" {
					continue
				}

				statefulset := &appsv1.StatefulSet{}
				if err := c.Get(ctx, types.NamespacedName{Name: r.Name, Namespace: pod.Namespace}, statefulset); client.IgnoreNotFound(err) != nil {
					_log.Error(err, "could not get statefulset", "name", r.Name, "namespace", pod.Namespace)
				}

				_log.V(9).Info("enqueue statefulset", "name", statefulset.Name, "namespace", statefulset.Namespace)

				return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: statefulset.Name, Namespace: statefulset.Namespace}}}
			}
		}

		return nil
	}
}
