/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sessionstore

import (
	"context"
	"github.com/go-logr/logr"
	"time"

	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// KubeSsoCleaner periodically deletes expired SsoSession resources.
// Expiration logic mirrors scs memstore: entries with expiry before now are removed.
// Additionally, if Deadline is set and is before now, the session is removed too.
type KubeSsoCleaner struct {
	client    client.Client
	namespace string
	interval  time.Duration
}

func NewKubeSsoCleaner(k8sClient client.Client, namespace string, interval time.Duration) *KubeSsoCleaner {
	return &KubeSsoCleaner{client: k8sClient, namespace: namespace, interval: interval}
}

// Start implements manager.Runnable. It runs until context is cancelled.
func (c *KubeSsoCleaner) Start(ctx context.Context) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	// Initial run
	c.cleanupOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.cleanupOnce(ctx)
		}
	}
}

func (c *KubeSsoCleaner) cleanupOnce(ctx context.Context) {
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Info("cleaning up sso session store", "namespace", c.namespace)
	now := time.Now()
	var list kubauthv1alpha1.SsoSessionList
	err := c.client.List(ctx, &list, client.InNamespace(c.namespace))
	if err != nil {
		logger.Error("failed to list SSOSessions", "err", err)
		return
	}
	for i := range list.Items {
		item := &list.Items[i]
		//logger.Info("Cleaning up SSO session", "session", item.Name)
		expired := false
		if !item.Spec.Expiry.IsZero() && now.After(item.Spec.Expiry.Time) {
			expired = true
		}
		if !expired && !item.Spec.Deadline.IsZero() && now.After(item.Spec.Deadline.Time) {
			expired = true
		}
		if expired {
			logger.Info("deleting expired session", "session", item.Name, "login", item.Spec.Login)
			_ = c.client.Delete(ctx, item)
		}
	}
}
