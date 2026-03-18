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
	"kubauth/cmd/oidc/oidcstorage"
	"log/slog"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const DefaultBCryptWorkFactor = 12

const finalizerName = "kubauth.kubotal.io/finalizer"

// OidcClientReconciler reconciles a OidcClient object
type OidcClientReconciler struct {
	client.Client
	record.EventRecorder
	Scheme                    *runtime.Scheme
	Namespace                 string // Where OidcClient are stored
	Storage                   *oidcstorage.MemoryStore
	statusErrorCount          int
	Logger                    *slog.Logger
	ClientPrivilegedNamespace string
}

func (r *OidcClientReconciler) buildClientId(spec *kubauthv1alpha1.OidcClientSpec, name string, namespace string) string {
	if spec.ClientId != "" {
		return spec.ClientId
	}
	if namespace != r.ClientPrivilegedNamespace {
		return fmt.Sprintf("%s-%s", namespace, name)
	}
	return name
}

// +kubebuilder:rbac:groups=kubauth.kubotal.io,resources=oidcclients,verbs=get;list;watch;patch;update
// +kubebuilder:rbac:groups=kubauth.kubotal.io,resources=oidcclients/status,verbs=get;update;patch

// Reconcile For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *OidcClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// _ = logf.FromContext(ctx)
	// Don't use this, has too context verbose
	//logger := logr.FromContextAsSlogLogger(ctx)

	logger := r.Logger.With("namespace", req.Namespace, "name", req.Name)

	ctx = logr.NewContextWithSlogLogger(ctx, logger)

	oidcClient := &kubauthv1alpha1.OidcClient{}
	err := r.Get(ctx, req.NamespacedName, oidcClient)
	if err != nil {
		// Deleted object (There is no finalizer in this implementation)
		logger.Debug("Unable to fetch resource. Seems deleted.")
		// we'll ignore not-found errors, since they can't be fixed by an immediate requeue
		// (we'll need to wait for a new notification), and we can get them on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if oidcClient.Status.ClientId == "" {
		// clientId is set on first run, then immutable
		// (We are sure status will ne updated as Phase == "" on first run)
		oidcClient.Status.ClientId = r.buildClientId(&oidcClient.Spec, req.Name, req.Namespace)
	}

	if !oidcClient.ObjectMeta.DeletionTimestamp.IsZero() {
		patch := client.MergeFrom(oidcClient.DeepCopy())
		// Deletion is requested. Remove from referential
		logger.Info("OidcClient is being deleted.")
		// Only 'Ready' client are registered in storage
		if oidcClient.Status.Phase == kubauthv1alpha1.OidcClientPhaseReady {
			r.Storage.DeleteClient(ctx, oidcClient.Status.ClientId)
		}
		controllerutil.RemoveFinalizer(oidcClient, finalizerName)
		logger.Debug(">-> Update resource (Remove finalizer)")
		if err := r.Patch(ctx, oidcClient, patch); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Not under deletion. Add a finalizer if not already set
	if !controllerutil.ContainsFinalizer(oidcClient, finalizerName) {
		patch := client.MergeFrom(oidcClient.DeepCopy())
		logger.Debug("Add finalizer")
		controllerutil.AddFinalizer(oidcClient, finalizerName)
		logger.Debug(">-> Update resource (Add finalizer)")
		err := r.Patch(ctx, oidcClient, patch)
		return ctrl.Result{}, err // we reschedule, to avoid an 'object has been modified' on next status update
		//if err != nil {
		//	return ctrl.Result{}, err
		//}
	}

	if oidcClient.Spec.Public {
		if oidcClient.Spec.Secrets != nil {
			return r.UpdateStorageAndStatus(ctx, oidcClient, nil, fmt.Errorf("'secrets' set while public is enabled"))
		}
		// OK. Just register it
		return r.UpdateStorageAndStatus(ctx, oidcClient, nil, nil)
	}

	if oidcClient.Spec.Secrets == nil || len(*oidcClient.Spec.Secrets) == 0 {
		return r.UpdateStorageAndStatus(ctx, oidcClient, nil, fmt.Errorf("when not public, one of 'secrets' must be defined with at least one item"))
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
				return r.UpdateStorageAndStatus(ctx, oidcClient, nil, fmt.Errorf("unable to fetch secret '%s:%s'", req.Namespace, secretRef.Name))
			}
			return ctrl.Result{}, err
		}
		valueBytes, exists := secret.Data[secretRef.Key]
		if !exists {
			return r.UpdateStorageAndStatus(ctx, oidcClient, nil, fmt.Errorf("no '%s' key in secret '%s:%s'", secretRef.Key, req.Namespace, secretRef.Name))
		}
		if secretRef.Hashed {
			hashedSecrets[idx] = valueBytes
		} else {
			hashedSecrets[idx], err = bcrypt.GenerateFromPassword(valueBytes, DefaultBCryptWorkFactor)
			if err != nil {
				return r.UpdateStorageAndStatus(ctx, oidcClient, nil, fmt.Errorf("unable to hash value from secret '%s:%s[%s]'", req.Namespace, secretRef.Name, secretRef.Key))
			}
		}
	}
	return r.UpdateStorageAndStatus(ctx, oidcClient, hashedSecrets, nil)
}

func (r *OidcClientReconciler) UpdateStorageAndStatus(ctx context.Context, oidcClient *kubauthv1alpha1.OidcClient, hashedSecrets [][]byte, err error) (ctrl.Result, error) {
	if err == nil {
		err = r.Storage.SetClient(ctx, oidcstorage.NewFositeClient(oidcClient, oidcClient.Status.ClientId, hashedSecrets))
		if err == nil {
			r.Event(oidcClient, "Normal", "Created", "Created client with client_id '"+oidcClient.Status.ClientId+"'")
		} else {
			r.Event(oidcClient, "Warning", "Duplicate", err.Error())
		}
		return r.updateStatus(ctx, oidcClient, err)
	}
	r.Event(oidcClient, "Warning", "Error", err.Error())
	r.Storage.DeleteClient(ctx, oidcClient.Status.ClientId)
	return r.updateStatus(ctx, oidcClient, err)
}

func (r *OidcClientReconciler) updateStatus(ctx context.Context, oidcClient *kubauthv1alpha1.OidcClient, err error) (ctrl.Result, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	message := "OK"
	phase := kubauthv1alpha1.OidcClientPhaseReady
	if err != nil {
		message = err.Error()
		phase = kubauthv1alpha1.OidcClientPhaseError
	}
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
	return ctrl.Result{}, nil
}
