// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"errors"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
)

// cleanupInactiveStacks deletes resources from ingress stacks that the target is no longer using.
// When a stack is already absent it does nothing. Deletion errors are
// aggregated; missing CRDs are tolerated (see the fetchOidcApps* helpers).
func cleanupInactiveStacks(ctx context.Context, c client.Client, target, owner client.Object) error {
	cfg := configuration.GetOIDCAppsControllerConfig()

	var errs []error

	_log := log.FromContext(ctx).WithValues("target", target.GetName(), "owner", owner.GetName())

	if !cfg.ShallCreateIngress(target) {
		ingresses, err := fetchOidcAppsIngress(ctx, c, owner)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list stale ingresses: %w", err))
		} else {
			for i := range ingresses.Items {
				ing := &ingresses.Items[i]
				if err := c.Delete(ctx, ing); client.IgnoreNotFound(err) != nil {
					errs = append(errs, fmt.Errorf("failed to delete stale ingress %s/%s: %w", ing.Namespace, ing.Name, err))

					continue
				}

				_log.V(9).Info("Deleted stale ingress", "name", ing.Name, "namespace", ing.Namespace)
			}
		}
	}

	if !cfg.ShallCreateHTTPRoute(target) {
		httpRoutes, err := fetchOidcAppsHTTPRoutes(ctx, c, owner)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list stale httproutes: %w", err))
		} else {
			for i := range httpRoutes.Items {
				route := &httpRoutes.Items[i]
				if err := c.Delete(ctx, route); client.IgnoreNotFound(err) != nil {
					errs = append(errs, fmt.Errorf("failed to delete stale httproute %s/%s: %w", route.Namespace, route.Name, err))

					continue
				}

				_log.V(9).Info("Deleted stale httproute", "name", route.Name, "namespace", route.Namespace)
			}
		}
	}

	if !cfg.ShallCreateIstioGateway(target) {
		virtualServices, err := fetchOidcAppsVirtualServices(ctx, c, owner)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list stale virtualservices: %w", err))
		} else {
			for _, vs := range virtualServices.Items {
				if err := c.Delete(ctx, vs); client.IgnoreNotFound(err) != nil {
					errs = append(errs, fmt.Errorf("failed to delete stale virtualservice %s/%s: %w", vs.Namespace, vs.Name, err))

					continue
				}

				_log.V(9).Info("Deleted stale virtualservice", "name", vs.Name, "namespace", vs.Namespace)
			}
		}

		gateways, err := fetchOidcAppsIstioGateways(ctx, c, owner)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list stale gateways: %w", err))
		} else {
			for _, gw := range gateways.Items {
				if err := c.Delete(ctx, gw); client.IgnoreNotFound(err) != nil {
					errs = append(errs, fmt.Errorf("failed to delete stale gateway %s/%s: %w", gw.Namespace, gw.Name, err))

					continue
				}

				_log.V(9).Info("Deleted stale gateway", "name", gw.Name, "namespace", gw.Namespace)
			}
		}

		destinationRules, err := fetchOidcAppsDestinationRules(ctx, c, owner)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list stale destinationrules: %w", err))
		} else {
			for _, dr := range destinationRules.Items {
				if err := c.Delete(ctx, dr); client.IgnoreNotFound(err) != nil {
					errs = append(errs, fmt.Errorf("failed to delete stale destinationrule %s/%s: %w", dr.Namespace, dr.Name, err))

					continue
				}

				_log.V(9).Info("Deleted stale destinationrule", "name", dr.Name, "namespace", dr.Namespace)
			}
		}
	}

	return errors.Join(errs...)
}
