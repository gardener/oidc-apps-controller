// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func isAnOwnedResource(owner, owned client.Object) bool {
	if owner == nil || owned == nil {
		return false
	}

	for _, ref := range owned.GetOwnerReferences() {
		if ref.UID == owner.GetUID() {
			return true
		}
	}

	return false
}

func deleteOwnedResources(ctx context.Context, c client.Client, object client.Object) error {
	var err error

	_log := log.FromContext(ctx).WithValues("uid", object.GetUID())

	secrets, err := fetchOidcAppsSecrets(ctx, c, object)
	if err != nil {
		return err
	}

	for _, secret := range secrets.Items {
		if err = c.Delete(ctx, &secret); err != nil {
			return errors.New("failed to delete")
		}

		_log.V(9).Info("Deleted", "name", secret.Name, "namespace", secret.Namespace)
	}

	ingresses, err := fetchOidcAppsIngress(ctx, c, object)
	if err != nil {
		return err
	}

	for _, ingress := range ingresses.Items {
		if err = c.Delete(ctx, &ingress); err != nil {
			return errors.New("failed to delete")
		}

		_log.V(9).Info("Deleted", "name", ingress.Name, "namespace", ingress.Namespace)
	}

	httpRoutes, err := fetchOidcAppsHTTPRoutes(ctx, c, object)
	if err != nil {
		return err
	}

	for _, route := range httpRoutes.Items {
		if err = c.Delete(ctx, &route); err != nil {
			return errors.New("failed to delete")
		}

		_log.V(9).Info("Deleted", "name", route.Name, "namespace", route.Namespace)
	}

	virtualServices, err := fetchOidcAppsVirtualServices(ctx, c, object)
	if err != nil {
		return err
	}

	for _, virtService := range virtualServices.Items {
		if err = c.Delete(ctx, virtService); err != nil {
			return errors.New("failed to delete")
		}

		_log.V(9).Info("Deleted", "name", virtService.Name, "namespace", virtService.Namespace)
	}

	gateways, err := fetchOidcAppsIstioGateways(ctx, c, object)
	if err != nil {
		return err
	}

	for _, gateway := range gateways.Items {
		if err = c.Delete(ctx, gateway); err != nil {
			return errors.New("failed to delete")
		}

		_log.V(9).Info("Deleted", "name", gateway.Name, "namespace", gateway.Namespace)
	}

	destinationRules, err := fetchOidcAppsDestinationRules(ctx, c, object)
	if err != nil {
		return err
	}

	for _, dr := range destinationRules.Items {
		if err = c.Delete(ctx, dr); err != nil {
			return errors.New("failed to delete")
		}

		_log.V(9).Info("Deleted", "name", dr.Name, "namespace", dr.Namespace)
	}

	services, err := fetchOidcAppsServices(ctx, c, object)
	if err != nil {
		return err
	}

	for _, service := range services.Items {
		if err = c.Delete(ctx, &service); err != nil {
			return errors.New("failed to delete")
		}

		_log.V(9).Info("Deleted", "name", service.Name, "namespace", service.Namespace)
	}

	return nil
}
