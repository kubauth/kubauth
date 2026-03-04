/*
Copyright (c) 2025 Kubotal.

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

package kubauthmodel

import (
	"context"
	"fmt"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	oidcstorage2 "kubauth/cmd/oidc/oidcstorage"
	"log/slog"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const DefaultBCryptWorkFactor = 12

// OidcClientReconciler reconciles a OidcClient object
type OidcClientReconciler struct {
	client.Client
	Scheme                    *runtime.Scheme
	Namespace                 string // Where OidcClient are stored
	Storage                   *oidcstorage2.MemoryStore
	statusErrorCount          int
	Logger                    *slog.Logger
	ClientPrivilegedNamespace string
}

func (r *OidcClientReconciler) buildClientId(name string, namespace string) string {
	if namespace != r.ClientPrivilegedNamespace {
		return fmt.Sprintf("%s-%s", namespace, name)
	}
	return name
}

// +kubebuilder:rbac:groups=kubauth.kubotal.io,resources=oidcclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kubauth.kubotal.io,resources=oidcclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kubauth.kubotal.io,resources=oidcclients/finalizers,verbs=update

// Reconcile For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *OidcClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// _ = logf.FromContext(ctx)
	// Don't use this, has too context verbose
	//logger := logr.FromContextAsSlogLogger(ctx)

	logger := r.Logger.With("namespace", req.Namespace, "name", req.Name)

	ctx = logr.NewContextWithSlogLogger(ctx, logger)

	clientId := r.buildClientId(req.Name, req.Namespace)

	oidcClient := &kubauthv1alpha1.OidcClient{}
	err := r.Get(ctx, req.NamespacedName, oidcClient)
	if err != nil {
		// Deleted object (There is no finalizer in this implementation)
		logger.Info("Unable to fetch resource. Seems deleted. Remove from referential")
		r.Storage.DeleteClient(ctx, clientId) // TODO: client_id for multi-tenancy
		// we'll ignore not-found errors, since they can't be fixed by an immediate requeue
		// (we'll need to wait for a new notification), and we can get them on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	oidcClient.Status.ClientId = clientId // Stored in first update, immutable after

	if oidcClient.Spec.Public {
		if oidcClient.Spec.Secrets != nil {
			return r.updateStatus(ctx, oidcClient, kubauthv1alpha1.OidcClientPhaseError, "'secrets' set while public is enabled")
		}
		// OK. Just register it
		r.Storage.SetClient(ctx, oidcstorage2.NewFositeClient(oidcClient, clientId, nil))
		return r.updateStatus(ctx, oidcClient, kubauthv1alpha1.OidcClientPhaseReady, "")
	}

	if oidcClient.Spec.Secrets == nil || len(*oidcClient.Spec.Secrets) == 0 {
		return r.updateStatus(ctx, oidcClient, kubauthv1alpha1.OidcClientPhaseError, "When not public, one of 'secrets' must be defined with at least one item")
	}
	hashedSecrets := make([][]byte, len(*oidcClient.Spec.Secrets))
	for idx, secretRef := range *oidcClient.Spec.Secrets {
		var secret corev1.Secret
		err = r.Get(ctx, types.NamespacedName{
			Name:      secretRef.Name,
			Namespace: req.Namespace,
		}, &secret)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return r.updateStatus(ctx, oidcClient, kubauthv1alpha1.OidcClientPhaseError, fmt.Sprintf("Unable to fetch secret '%s:%s'", secretRef.Name, req.Namespace))
			}
			return ctrl.Result{}, err
		}
		valueBytes, exists := secret.Data[secretRef.Key]
		if !exists {
			return r.updateStatus(ctx, oidcClient, kubauthv1alpha1.OidcClientPhaseError, fmt.Sprintf("No '%s' key in secret '%s:%s'", secretRef.Key, secretRef.Name, req.Namespace))
		}
		if secretRef.Hashed {
			hashedSecrets[idx] = valueBytes
		} else {
			hashedSecrets[idx], err = bcrypt.GenerateFromPassword(valueBytes, DefaultBCryptWorkFactor)
			if err != nil {
				return r.updateStatus(ctx, oidcClient, kubauthv1alpha1.OidcClientPhaseError, fmt.Sprintf("Unable to hash value from secret '%s:%s[%s]'", secretRef.Name, req.Namespace, secretRef.Key))
			}
		}
	}
	r.Storage.SetClient(ctx, oidcstorage2.NewFositeClient(oidcClient, clientId, hashedSecrets))
	return r.updateStatus(ctx, oidcClient, kubauthv1alpha1.OidcClientPhaseReady, "")
}

func (r *OidcClientReconciler) updateStatus(ctx context.Context, oidcClient *kubauthv1alpha1.OidcClient, phase kubauthv1alpha1.OidcClientPhase, message string) (ctrl.Result, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	toUpdate := false
	if oidcClient.Status.Phase != phase {
		oidcClient.Status.Phase = phase
		toUpdate = true
	}
	if oidcClient.Status.Message != message {
		oidcClient.Status.Message = message
		toUpdate = true
	}
	if toUpdate {
		logger.Debug("OidcClient.Status will be updated", "phase", phase, "message", message)
		err := r.Status().Update(ctx, oidcClient)
		if err != nil {
			if r.statusErrorCount == 0 {
				// If this is the first error, don't use the usual CrashLoopBackOff, but retry
				r.statusErrorCount++
				logger.Debug("Error updating status. Hidden as first one", "phase", phase)
				return ctrl.Result{RequeueAfter: time.Millisecond * 200}, nil
			}
			return ctrl.Result{}, err
		}
	} else {
		logger.Debug("OidcClient.Status is up to date. No update", "phase", phase, "message", message)
	}
	if oidcClient.Status.Phase == kubauthv1alpha1.OidcClientPhaseError {
		// Remove from referential if in error
		r.Storage.DeleteClient(ctx, r.buildClientId(oidcClient.Name, oidcClient.Namespace))
	}
	return ctrl.Result{}, nil
}
