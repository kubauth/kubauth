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

	logger.Info("Login logs cleaner started")

	// Run cleanup immediately on start
	cleanupAudit(ctx, kubeClient, logger)

	for {
		select {
		case <-ctx.Done():
			logger.Info("Login logs cleaner stopping due to context cancellation")
			return
		case <-ticker.C:
			cleanupAudit(ctx, kubeClient, logger)
		}
	}
}

// cleanupAudit removes Login records older than loginLifetime
func cleanupAudit(ctx context.Context, kubeClient client.Client, logger *slog.Logger) {
	cutoffTime := time.Now().Add(-auditParams.loginLifetime)

	logger.Debug("Starting login logs cleanup", "cutoffTime", cutoffTime, "namespace", auditParams.namespace)

	// List all Login records in the namespace
	loginList := &kubauthv1alpha1.LoginList{}
	listOpts := &client.ListOptions{
		Namespace: auditParams.namespace,
	}

	err := kubeClient.List(ctx, loginList, listOpts)
	if err != nil {
		logger.Error("Failed to list login records for cleanup", "error", err, "namespace", auditParams.namespace)
		return
	}

	deletedCount := 0
	errorCount := 0

	for _, login := range loginList.Items {
		// Check if the login record is older than the cutoff time
		if login.Spec.When.Time.Before(cutoffTime) {
			logger.Debug("Deleting expired login record",
				"name", login.Name,
				"login", login.Spec.User.Login,
				"when", login.Spec.When.Time,
				"age", time.Since(login.Spec.When.Time))

			err := kubeClient.Delete(ctx, &login)
			if err != nil {
				logger.Error("Failed to delete expired login record",
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
		logger.Info("Login logs cleanup completed",
			"totalRecords", len(loginList.Items),
			"deletedCount", deletedCount,
			"errorCount", errorCount,
			"cutoffTime", cutoffTime)
	} else {
		logger.Info("Login logs cleanup completed - no records to delete",
			"totalRecords", len(loginList.Items),
			"cutoffTime", cutoffTime)
	}
}

/*
	Setup a login logs cleaning process, erasing login logs older than auditParams.loginLifetime and running every auditParams.cleanupPeriod

*/
