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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/yaml"

	constants "github.com/gardener/oidc-apps-controller/pkg/constants"
)

var _ manager.Runnable = &gardenerAccessTokenNotifier{}

type gardenerAccessTokenNotifier struct {
	kubeconfigPath string
	tokenPath      string
	hashes         map[string]string
	client         client.Client
}

var _log = logf.Log.WithName("gardener-access-token-notifier")

// NewGardenerAccessTokenNotifier is a controller-runtime runnable used to propagate gardener access tokens to the targets
func NewGardenerAccessTokenNotifier(c client.Client, kubeconfigPath, tokenPath string) manager.Runnable {
	_log.Info("Creating notifier", "kubeconfig", kubeconfigPath, "token", tokenPath)

	return &gardenerAccessTokenNotifier{
		kubeconfigPath: kubeconfigPath,
		tokenPath:      tokenPath,
		client:         c,
		hashes: map[string]string{
			"kubeconfig": getFileSha256(kubeconfigPath),
			"token":      getFileSha256(tokenPath),
		},
	}
}

// Start implements the controller-runtime runnable interface
func (g *gardenerAccessTokenNotifier) Start(ctx context.Context) error {
	_log.Info("Starting notifier", "kubeconfig", g.kubeconfigPath, "token", g.tokenPath)
	hashChan := g.startCalculateHashPath(ctx)

	go func(ctx context.Context) {
		for range hashChan {
			g.updateSecrets(ctx)
		}
	}(ctx)

	// Updating secrets upon controller restart
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
				kubeconfigHash := getFileSha256(g.kubeconfigPath)
				if kubeconfigHash != g.hashes["kubeconfig"] {
					g.hashes["kubeconfig"] = kubeconfigHash
					hashPathChan <- kubeconfigHash

					continue
				}

				tokenHash := getFileSha256(g.tokenPath)
				if tokenHash != g.hashes["token"] {
					g.hashes["token"] = tokenHash
					hashPathChan <- tokenHash
				}
			case <-ctx.Done():
				ticker.Stop()
				close(hashPathChan)

				return
			}
		}
	}()

	return hashPathChan
}

func (g *gardenerAccessTokenNotifier) updateSecrets(ctx context.Context) {
	tokenBytes, err := os.ReadFile(g.tokenPath)
	if err != nil {
		_log.Error(err, "error reading access token")

		return
	}

	tokenBytes = bytes.TrimSpace(tokenBytes)
	kubeConfigBytes, err := os.ReadFile(g.kubeconfigPath)

	if err != nil {
		_log.Error(err, "error reading kubeconfig")

		return
	}

	kubeConfigBytes = bytes.TrimSpace(kubeConfigBytes)
	kubeConfig := clientcmdv1.Config{}

	if err = yaml.Unmarshal(kubeConfigBytes, &kubeConfig); err != nil {
		_log.Error(err, "error unmarshaling kubeconfig")
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
		_log.Error(err, "error marshaling kubeconfig")
	}

	kubeConfigList := &corev1.SecretList{}
	if err = g.client.List(ctx, kubeConfigList,
		client.MatchingLabelsSelector{
			Selector: labels.SelectorFromSet(map[string]string{constants.SecretLabelKey: constants.KubeconfigLabelValue}),
		},
	); err != nil {
		_log.Error(err, "error fetching kubeconfig secretes")

		return
	}

	for _, secret := range kubeConfigList.Items {
		// Check if there is a difference between the target secret and the current kubeconfig
		if targetKubeconfig, ok := secret.Data["kubeconfig"]; ok {
			if bytes.Equal(targetKubeconfig, kubeconfigBytes) {
				_log.V(9).Info("No kubeconfig change in the target secret, skipping",
					"secret namespace/name", secret.GetNamespace()+"/"+secret.GetName(),
				)

				continue
			}
		}

		secret.StringData = map[string]string{"kubeconfig": string(kubeconfigBytes)}
		if err := g.client.Update(ctx, &secret); err != nil {
			_log.Error(err, "cannot update kubeconfig secret",
				"secret namespace/name", secret.GetNamespace()+"/"+secret.GetName(),
			)
		}

		_log.Info("Secret is updated",
			"secret namespace/name", secret.GetNamespace()+"/"+secret.GetName(),
		)
	}
}
