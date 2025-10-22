/*
Copyright (c) Kubotal 2025.

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

package audit

import (
	"context"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"log/slog"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// startAuditCleaner starts a background process that periodically cleans up old login logs
func startAuditCleaner(ctx context.Context, kubeClient client.Client, logger *slog.Logger) {
	ticker := time.NewTicker(auditParams.cleanupPeriod)
	defer ticker.Stop()

	logger.Info("LoginAttempt logs cleaner started")

	// Run cleanup immediately on start
	cleanupAudit(ctx, kubeClient, logger)

	for {
		select {
		case <-ctx.Done():
			logger.Info("LoginAttempt logs cleaner stopping due to context cancellation")
			return
		case <-ticker.C:
			cleanupAudit(ctx, kubeClient, logger)
		}
	}
}

// cleanupAudit removes LoginAttempt records older than recordLifetime
func cleanupAudit(ctx context.Context, kubeClient client.Client, logger *slog.Logger) {
	cutoffTime := time.Now().Add(-auditParams.recordLifetime)

	logger.Debug("Starting loginAttempt logs cleanup", "cutoffTime", cutoffTime, "namespace", auditParams.namespace)

	// List all LoginAttempt records in the namespace
	loginAttemptList := &kubauthv1alpha1.LoginAttemptList{}
	listOpts := &client.ListOptions{
		Namespace: auditParams.namespace,
	}

	err := kubeClient.List(ctx, loginAttemptList, listOpts)
	if err != nil {
		logger.Error("Failed to list login records for cleanup", "error", err, "namespace", auditParams.namespace)
		return
	}

	deletedCount := 0
	errorCount := 0

	for _, login := range loginAttemptList.Items {
		// Check if the login record is older than the cutoff time
		if login.Spec.When.Time.Before(cutoffTime) {
			logger.Debug("Deleting expired loginAttempt record",
				"name", login.Name,
				"login", login.Spec.User.Login,
				"when", login.Spec.When.Time,
				"age", time.Since(login.Spec.When.Time))

			err := kubeClient.Delete(ctx, &login)
			if err != nil {
				logger.Error("Failed to delete expired loginAttempt record",
					"error", err,
					"name", login.Name,
					"login", login.Spec.User.Login)
				errorCount++
			} else {
				deletedCount++
			}
		}
	}

	if deletedCount > 0 || errorCount > 0 {
		logger.Info("LoginAttempt logs cleanup completed",
			"totalRecords", len(loginAttemptList.Items),
			"deletedCount", deletedCount,
			"errorCount", errorCount,
			"cutoffTime", cutoffTime)
	} else {
		logger.Info("LoginAttempt logs cleanup completed - no records to delete",
			"totalRecords", len(loginAttemptList.Items),
			"cutoffTime", cutoffTime)
	}
}

/*
	Setup a login logs cleaning process, erasing login logs older than auditParams.recordLifetime and running every auditParams.cleanupPeriod

*/
