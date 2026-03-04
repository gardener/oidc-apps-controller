// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package healthz

import (
	"context"
	"errors"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

// NewCacheSyncHealthz returns a healthz.Checker that verifies the cache has synced.
func NewCacheSyncHealthz(c cache.Cache) healthz.Checker {
	return func(req *http.Request) error {
		// Create a context with timeout for the sync check
		ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
		defer cancel()

		// WaitForCacheSync will return true if the cache has synced
		if !c.WaitForCacheSync(ctx) {
			return errors.New("cache has not synced yet")
		}

		return nil
	}
}
