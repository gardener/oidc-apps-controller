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

package controllers

import (
	"context"
	"fmt"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func logOwnedResources(ctx context.Context, c client.Client, object client.Object) {

	secb := strings.Builder{}
	secb.WriteString("[")

	secrets, _ := fetchOidcAppsSecrets(ctx, c, object)
	for i, s := range secrets.Items {
		secb.WriteString(s.Namespace + "/" + s.Name)
		if i < (len(secrets.Items) - 1) {
			secb.WriteString(", ")
		}
	}
	secb.WriteString("]")

	srvb := strings.Builder{}
	srvb.WriteString("[")
	services, _ := fetchOidcAppsServices(ctx, c, object)
	for i, s := range services.Items {
		srvb.WriteString(s.Namespace + "/" + s.Name)
		if i < (len(services.Items) - 1) {
			srvb.WriteString(", ")
		}
	}
	srvb.WriteString("]")

	ingb := strings.Builder{}
	ingb.WriteString("[")
	ingresses, _ := fetchOidcAppsIngress(ctx, c, object)
	for i, s := range ingresses.Items {
		ingb.WriteString(s.Namespace + "/" + s.Name)
		if i < (len(ingresses.Items) - 1) {
			ingb.WriteString(", ")
		}
	}
	ingb.WriteString("]")

	log.FromContext(ctx).V(9).Info("Owning resources", "secrets", secb.String(), "services", srvb.String(), "ingresses",
		ingb.String())

}

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
			return fmt.Errorf("failed to delete")
		}
		_log.V(9).Info("Deleted", "name", s.Name, "namespace", s.Namespace)
	}
	ingresses, err := fetchOidcAppsIngress(ctx, c, object)
	if err != nil {
		return err
	}
	for _, s := range ingresses.Items {
		if err = c.Delete(ctx, &s); err != nil {
			return fmt.Errorf("failed to delete")
		}
		_log.V(9).Info("Deleted", "name", s.Name, "namespace", s.Namespace)
	}
	services, err := fetchOidcAppsServices(ctx, c, object)
	if err != nil {
		return err
	}
	for _, s := range services.Items {
		if err = c.Delete(ctx, &s); err != nil {
			return fmt.Errorf("failed to delete")
		}
		_log.V(9).Info("Deleted", "name", s.Name, "namespace", s.Namespace)
	}
	return nil
}
