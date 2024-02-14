// Copyright 2024 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oidc_apps_controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gardener/oidc-apps-controller/pkg/certificates"
	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/controllers"
	"github.com/gardener/oidc-apps-controller/pkg/notifiers"
	oidcappswebhook "github.com/gardener/oidc-apps-controller/pkg/webhook"

	gardenextensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	gardenerhealthz "github.com/gardener/gardener/pkg/healthz"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var extensionConfig *configuration.OIDCAppsControllerConfig
var predicates predicate.GenerationChangedPredicate
var once sync.Once
var _log = logf.Log

// RunController is the entry point for initialzing and starting the controller-runtime manager
func RunController(ctx context.Context, o *OidcAppsControllerOptions) error {
	printGardenEnvVars()

	// Initialize a scheme which will contain the API definitions
	sch := scheme.Scheme

	// Add core Kubernetes schemes
	if err := scheme.AddToScheme(sch); err != nil {
		return err
	}

	// Add additional scheme in case of running in gardener cluster
	if len(os.Getenv(constants.GARDEN_KUBECONFIG)) > 0 {
		// Add gardener Cluster schemes
		if err := gardenextensionsv1alpha1.AddToScheme(sch); err != nil {
			return fmt.Errorf("could not initialize the runtime scheme: %w", err)
		}
	}

	// NAMESPACE is a required environment variable for the oidc-apps-controller certificate manager
	if !o.useCertManager && os.Getenv(constants.NAMESPACE) == "" {
		return errors.New("NAMESPACE environment variable is not set")
	}
	// NAMESPACE is a required environment variable for the image pull secret reconciler
	if o.registrySecret != "" && os.Getenv(constants.NAMESPACE) == "" {
		return errors.New("NAMESPACE environment variable is not set")
	}

	cfg := config.GetConfigOrDie()
	cfg.QPS = float32(100)
	cfg.Burst = 130

	mgr, err := manager.New(cfg,
		manager.Options{
			Scheme:                        sch,
			LeaderElection:                true,
			LeaderElectionID:              "oidc-apps-controller",
			LeaderElectionNamespace:       os.Getenv(constants.NAMESPACE),
			LeaseDuration:                 ptr.To(15 * time.Second),
			RenewDeadline:                 ptr.To(10 * time.Second),
			RetryPeriod:                   ptr.To(2 * time.Second),
			LeaderElectionReleaseOnCancel: true,
			HealthProbeBindAddress:        ":8081",
		},
	)
	if err != nil {
		return fmt.Errorf("could not initialize the controller-runtime manager: %w", err)
	}

	// Set domain name if we are running in a gardener cluster
	if len(os.Getenv(constants.GARDEN_KUBECONFIG)) > 0 && os.Getenv(constants.GARDEN_SEED_DOMAIN_NAME) == "" {
		if err := setGardenDomainNameEnvVar(ctx, mgr.GetConfig()); err != nil {
			return fmt.Errorf("could not set the garden domain name: %w", err)
		}
	}

	extensionConfig = configuration.CreateControllerConfigOrDie(
		o.controllerConfigPath,
		configuration.WithClient(mgr.GetClient()),
		configuration.WithLog(mgr.GetLogger()),
	)

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

	if err := addGardenAcceessTokenManager(mgr); err != nil {
		return fmt.Errorf("could not initialize gardener access token manager: %w", err)
	}

	if err := addPrivateRegistrySecretControllers(mgr, o); err != nil {
		return fmt.Errorf("could not initialize private registry secret manager: %w", err)
	}

	if err := addWebhooks(mgr, o); err != nil {
		return fmt.Errorf("could not initialize mutating webhooks: %w", err)
	}

	if err := mgr.AddReadyzCheck("informer-sync", gardenerhealthz.NewCacheSyncHealthz(mgr.GetCache())); err != nil {
		return fmt.Errorf("could not initialize controller readycheck: %w", err)
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
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

func setGardenDomainNameEnvVar(ctx context.Context, config *rest.Config) error {
	c, err := client.New(config, client.Options{})
	if err != nil {
		return fmt.Errorf("could not initialize the controller-runtime client: %w", err)
	}
	ingress := &networkingv1.Ingress{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "garden", Name: "kube-apiserver"}, ingress); err != nil {
		return fmt.Errorf("could not get kube-apiserver ingress: %w", err)
	}
	if len(ingress.Spec.Rules) > 0 {
		_, h, ok := strings.Cut(ingress.Spec.Rules[0].Host, ".")
		if ok {
			if err := os.Setenv(constants.GARDEN_SEED_DOMAIN_NAME, h); err != nil {
				return fmt.Errorf("could not set the garden domain name: %w", err)
			}
			_log.Info("Set domain name env variable", constants.GARDEN_SEED_DOMAIN_NAME, h)
		}
	}
	return nil
}

func fetchPredicates(extensionConfig *configuration.OIDCAppsControllerConfig) predicate.GenerationChangedPredicate {

	once.Do(
		func() {
			predicates = predicate.GenerationChangedPredicate{
				Funcs: predicate.Funcs{
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
		func(o client.Object) []string {
			secret := o.(*corev1.Secret)
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
		func(o client.Object) []string {
			service := o.(*corev1.Service)
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
		func(o client.Object) []string {
			ingress := o.(*networkingv1.Ingress)
			if value, exists := ingress.GetLabels()[constants.LabelKey]; exists {
				return []string{value}
			}
			return nil
		},
	); err != nil {
		return fmt.Errorf("could not set up the oidc-app-controller %T index: %w", networkingv1.Ingress{}, err)
	}
	return nil
}

func addDeploymentController(mgr manager.Manager) error {
	return controllerruntime.NewControllerManagedBy(mgr).
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
		Complete(&controllers.DeploymentReconciler{Client: mgr.GetClient()})
}

func addStatefulSetController(mgr manager.Manager) error {
	return controllerruntime.NewControllerManagedBy(mgr).
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
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				service := obj.(*corev1.Service)
				c := mgr.GetClient()
				for _, o := range service.GetOwnerReferences() {
					pod := &corev1.Pod{}
					if err := c.Get(ctx, types.NamespacedName{Name: o.Name, Namespace: service.Namespace}, pod); client.IgnoreNotFound(err) != nil {
						_log.Error(err, "could not get pod", "name", o.Name, "namespace", service.Namespace)
					}
					if len(pod.Name) == 0 {
						continue
					}

					for _, r := range pod.GetOwnerReferences() {
						statefulset := &appsv1.StatefulSet{}
						if err := c.Get(ctx, types.NamespacedName{Name: r.Name, Namespace: pod.Namespace}, statefulset); client.IgnoreNotFound(err) != nil {
							_log.Error(err, "could not get statefulset", "name", r.Name, "namespace", pod.Namespace)
						}
						if len(statefulset.Name) == 0 {
							continue
						}
						return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: statefulset.Name, Namespace: statefulset.Namespace}}}
					}
				}

				return nil
			}),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&networkingv1.Ingress{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				ingress := obj.(*networkingv1.Ingress)
				c := mgr.GetClient()
				for _, o := range ingress.GetOwnerReferences() {
					pod := &corev1.Pod{}
					if err := c.Get(ctx, types.NamespacedName{Name: o.Name, Namespace: ingress.Namespace}, pod); client.IgnoreNotFound(err) != nil {
						_log.Error(err, "could not get pod", "name", o.Name, "namespace", ingress.Namespace)
					}
					if len(pod.Name) == 0 {
						continue
					}

					for _, r := range pod.GetOwnerReferences() {
						statefulset := &appsv1.StatefulSet{}
						if err := c.Get(ctx, types.NamespacedName{Name: r.Name, Namespace: pod.Namespace}, statefulset); client.IgnoreNotFound(err) != nil {
							_log.Error(err, "could not get statefulset", "name", r.Name, "namespace", pod.Namespace)
						}
						if len(statefulset.Name) == 0 {
							continue
						}
						return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: statefulset.Name, Namespace: statefulset.Namespace}}}
					}
				}

				return nil
			}),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Complete(&controllers.StatefulSetReconciler{Client: mgr.GetClient()})
}

// Add certificate manager in case no external certificate manager is available
func addWebhookCertificateManager(mgr manager.Manager, o *OidcAppsControllerOptions) error {

	if !o.useCertManager {
		webhookKey := types.NamespacedName{
			Namespace: os.Getenv(constants.NAMESPACE),
			Name:      o.webhookName,
		}
		certManager, err := certificates.New(o.webhookCertsDir, webhookKey, mgr.GetClient(), mgr.GetConfig())
		if err != nil {
			return err
		}
		return mgr.Add(certManager)
	}

	return nil
}

func addGardenAcceessTokenManager(mgr manager.Manager) error {
	// Add garden-secret-notifier if the GARDEN environment variables are present
	if os.Getenv(constants.GARDEN_KUBECONFIG) != "" || os.Getenv(constants.GARDEN_ACCESS_TOKEN) != "" {
		kubeconfigPath := filepath.Dir(os.Getenv(constants.GARDEN_KUBECONFIG))
		tokenPath := os.Getenv(constants.GARDEN_ACCESS_TOKEN)
		if tokenPath == "" {
			tokenPath = filepath.Dir(os.Getenv(constants.GARDEN_KUBECONFIG))
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
func addPrivateRegistrySecretControllers(mgr manager.Manager, o *OidcAppsControllerOptions) error {

	if o.registrySecret != "" {
		imagePullSecretPredicates := predicate.GenerationChangedPredicate{
			Funcs: predicate.Funcs{
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

func addWebhooks(mgr manager.Manager, o *OidcAppsControllerOptions) error {
	// Add Mutating Admission Webhook Server
	webhookServer := webhook.NewServer(webhook.Options{
		Port:    o.webhookPort,
		CertDir: o.webhookCertsDir,
	})

	webhookServer.Register(
		constants.DeploymentWebHookPath,
		&webhook.Admission{Handler: &oidcappswebhook.DeploymentMutator{
			Client:          mgr.GetClient(),
			Decoder:         admission.NewDecoder(scheme.Scheme),
			ImagePullSecret: o.registrySecret,
		}},
	)

	webhookServer.Register(
		constants.StatefulsetWebHookPath,
		&webhook.Admission{Handler: &oidcappswebhook.StatefulSetMutator{
			Client:          mgr.GetClient(),
			Decoder:         admission.NewDecoder(scheme.Scheme),
			ImagePullSecret: o.registrySecret,
		}},
	)

	webhookServer.Register(
		constants.PodWebHookPath,
		&webhook.Admission{Handler: &oidcappswebhook.PodMutator{
			Client:  mgr.GetClient(),
			Decoder: admission.NewDecoder(scheme.Scheme),
		}},
	)

	// Add the server to the manager
	return mgr.Add(webhookServer)

}
