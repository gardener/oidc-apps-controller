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

package notifiers

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/yaml"

	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/constants"
)

var _ manager.Runnable = &gardenerAccessTokenNotifier{}

type gardenerAccessTokenNotifier struct {
	tokenPath string
	pathHash  string
	client    client.Client
	log       logr.Logger
}

// NewGardenerAccessTokenNotifier is a controller-runtime runnable used to propagate gardener access tokens to the targets
func NewGardenerAccessTokenNotifier(c client.Client, path string) manager.Runnable {
	return &gardenerAccessTokenNotifier{
		tokenPath: path,
		client:    c,
	}
}

// Start implements the controler-runtime runnable interface
func (g *gardenerAccessTokenNotifier) Start(ctx context.Context) error {
	g.log = log.FromContext(ctx).WithName("gardener access token")
	g.pathHash = getTotalHash(g.log, g.tokenPath)

	g.log.Info("Starting notifier", "path", g.tokenPath)
	hashChan := g.startCalculateHashPath(ctx)
	g.pathHash = <-hashChan
	go func(ctx context.Context) {
		for current := range hashChan {
			if g.pathHash == current {
				continue
			}
			g.updateSecrets(ctx)
			g.pathHash = current
		}
	}(ctx)

	//Updating secrets upon controller restart
	g.updateSecrets(ctx)
	return nil
}

func (g *gardenerAccessTokenNotifier) startCalculateHashPath(ctx context.Context) <-chan string {

	hashPathChan := make(chan string, 2)
	ticker := time.NewTicker(3 * time.Second)

	go func() {
		for {
			select {
			case <-ticker.C:
				hashPathChan <- getTotalHash(g.log, g.tokenPath)
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
	return hashPathChan
}

func (g *gardenerAccessTokenNotifier) updateSecrets(ctx context.Context) {

	tokenBytes, err := os.ReadFile(filepath.Join(g.tokenPath, "token"))
	if err != nil {
		g.log.Error(err, "error reading access token")
		return
	}
	tokenBytes = bytes.TrimSpace(tokenBytes)
	kubeConfigBytes, err := os.ReadFile(filepath.Join(g.tokenPath, "kubeconfig"))
	if err != nil {
		g.log.Error(err, "error reading kubeconfig")
		return
	}
	kubeConfigBytes = bytes.TrimSpace(kubeConfigBytes)

	kubeConfig := clientcmdv1.Config{}
	if err = yaml.Unmarshal(kubeConfigBytes, &kubeConfig); err != nil {
		g.log.Error(err, "error unmarshaling kubeconfig")
	}

	for i, n := range kubeConfig.AuthInfos {
		if n.Name != "extension" {
			continue
		}
		kubeConfig.AuthInfos[i].AuthInfo.TokenFile = ""
		kubeConfig.AuthInfos[i].AuthInfo.Token = string(tokenBytes)
	}

	kubeconfigBytes, err := yaml.Marshal(kubeConfig)
	if err != nil {
		g.log.Error(err, "error marshaling kubeconfig")
	}

	kubeConfigList := &v1.SecretList{}
	if err = g.client.List(ctx, kubeConfigList,
		client.MatchingLabelsSelector{
			Selector: labels.SelectorFromSet(map[string]string{oidc_apps_controller.LabelKey: "kubeconfig"}),
		},
	); err != nil {
		g.log.Error(err, "error fetching kubeconfig secretes")
		return
	}
	for _, secret := range kubeConfigList.Items {

		//Check if there is a difference between the target secret and the current kubeconfig
		if targetKubeconfig, ok := secret.Data["kubeconfig"]; ok {
			if bytes.Equal(targetKubeconfig, kubeconfigBytes) {
				g.log.V(9).Info("No kubeconfig change in the target secret, skipping",
					"secret namespace/name", secret.GetNamespace()+"/"+secret.GetName(),
				)
				continue
			}
		}

		secret.StringData = map[string]string{"kubeconfig": string(kubeconfigBytes)}
		if err := g.client.Update(ctx, &secret); err != nil {
			g.log.Error(err, "cannot update kubeconfig secret",
				"secret namespace/name", secret.GetNamespace()+"/"+secret.GetName(),
			)
		}
		g.log.Info("Secret is updated",
			"secret namespace/name", secret.GetNamespace()+"/"+secret.GetName(),
		)
	}
}
