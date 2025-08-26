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

	for _, s := range secrets.Items {
		if err = c.Delete(ctx, &s); err != nil {
			return errors.New("failed to delete")
		}

		_log.V(9).Info("Deleted", "name", s.Name, "namespace", s.Namespace)
	}

	ingresses, err := fetchOidcAppsIngress(ctx, c, object)
	if err != nil {
		return err
	}

	for _, s := range ingresses.Items {
		if err = c.Delete(ctx, &s); err != nil {
			return errors.New("failed to delete")
		}

		_log.V(9).Info("Deleted", "name", s.Name, "namespace", s.Namespace)
	}

	services, err := fetchOidcAppsServices(ctx, c, object)
	if err != nil {
		return err
	}

	for _, s := range services.Items {
		if err = c.Delete(ctx, &s); err != nil {
			return errors.New("failed to delete")
		}

		_log.V(9).Info("Deleted", "name", s.Name, "namespace", s.Namespace)
	}

	return nil
}
