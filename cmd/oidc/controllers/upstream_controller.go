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

package controllers

import (
	"context"
	"fmt"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"kubauth/cmd/oidc/oidcstorage"
	"kubauth/cmd/oidc/upstreams"
	"log/slog"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// UpstreamProviderReconciler reconciles a UpstreamProvider object
type UpstreamProviderReconciler struct {
	client.Client
	record.EventRecorder
	Scheme           *runtime.Scheme
	Storage          *oidcstorage.MemoryStore
	statusErrorCount int
	Logger           *slog.Logger
}

func (r *UpstreamProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// _ = logf.FromContext(ctx)
	// Don't use this, has too context verbose
	//logger := logr.FromContextAsSlogLogger(ctx)

	logger := r.Logger.With("namespace", req.Namespace, "name", req.Name)

	ctx = logr.NewContextWithSlogLogger(ctx, logger)

	upstreamProvider := &kubauthv1alpha1.UpstreamProvider{}
	err := r.Get(ctx, req.NamespacedName, upstreamProvider)
	if err != nil {
		// Deleted object (There is no finalizer in this implementation)
		logger.Debug("Unable to fetch resource. Seems deleted.")
		// we'll ignore not-found errors, since they can't be fixed by an immediate requeue
		// (we'll need to wait for a new notification), and we can get them on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !upstreamProvider.ObjectMeta.DeletionTimestamp.IsZero() {
		patch := client.MergeFrom(upstreamProvider.DeepCopy())
		// Deletion is requested. Remove from referential
		logger.Info("UpstreamProvider is being deleted.")
		// Only 'Ready' client are registered in storage
		if upstreamProvider.Status.Phase == kubauthv1alpha1.UpstreamProviderPhaseReady {
			r.Storage.DeleteClient(ctx, upstreamProvider.Name)
		}
		controllerutil.RemoveFinalizer(upstreamProvider, finalizerName)
		logger.Debug(">-> Update resource (Remove finalizer)")
		if err := r.Patch(ctx, upstreamProvider, patch); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Not under deletion. Add a finalizer if not already set
	if !controllerutil.ContainsFinalizer(upstreamProvider, finalizerName) {
		patch := client.MergeFrom(upstreamProvider.DeepCopy())
		logger.Debug("Add finalizer")
		controllerutil.AddFinalizer(upstreamProvider, finalizerName)
		logger.Debug(">-> Update resource (Add finalizer)")
		err := r.Patch(ctx, upstreamProvider, patch)
		return ctrl.Result{}, err // we reschedule, to avoid an 'object has been modified' on next status update
		//if err != nil {
		//	return ctrl.Result{}, err
		//}
	}

	if upstreamProvider.Spec.Type == kubauthv1alpha1.UpstreamProviderTypeInternal {
		upstream, _ := upstreams.NewUpstream(ctx, upstreamProvider, "", "")
		r.Storage.SetUpstream(upstream)
		return ctrl.Result{}, nil
	}
	// Check input values (Most of this are to be replicated in a webhook
	err = func() error {
		spec := upstreamProvider.Spec
		if spec.Type != kubauthv1alpha1.UpstreamProviderTypeOidc {
			return fmt.Errorf("upstream provider type %s is not supported", spec.Type)
		}
		if spec.DisplayName == "" {
			return fmt.Errorf("upstream provider has no displayName")
		}
		if spec.IssuerURL == "" {
			return fmt.Errorf("upstream provider has no issuerURL")
		}
		if spec.RedirectURL == "" {
			return fmt.Errorf("upstream provider has no redirectURL")
		}
		if spec.ClientId == "" {
			return fmt.Errorf("upstream provider has no clientId")
		}
		if spec.Scopes == nil || len(spec.Scopes) == 0 {
			return fmt.Errorf("upstream provider has no scopes")
		}
		return nil
	}()
	if err != nil {
		return r.updateStatus(ctx, upstreamProvider, nil, err)
	}

	// Must fetch clientSecret
	clientSecret := ""
	if upstreamProvider.Spec.ClientSecret != nil {
		// TODO: Fetch secret
	}

	caData := ""
	if upstreamProvider.Spec.CertificateAuthority != nil {
		// TODO: Fetch caData
	}

	upstream, err := upstreams.NewUpstream(ctx, upstreamProvider, clientSecret, caData)
	if err != nil {
		return r.updateStatus(ctx, upstreamProvider, upstream, err)
	}
	r.Storage.SetUpstream(upstream)
	return r.updateStatus(ctx, upstreamProvider, upstream, err)
}

func (r *UpstreamProviderReconciler) updateStatus(ctx context.Context, upstreamProvider *kubauthv1alpha1.UpstreamProvider, upstream upstreams.Upstream, err error) (ctrl.Result, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	message := "OK"
	phase := kubauthv1alpha1.UpstreamProviderPhaseReady
	if err != nil {
		message = err.Error()
		phase = kubauthv1alpha1.UpstreamProviderPhaseError
	}
	toUpdate := false
	if upstreamProvider.Status.Phase != phase {
		upstreamProvider.Status.Phase = phase
		toUpdate = true
	}
	if upstreamProvider.Status.Message != message {
		upstreamProvider.Status.Message = message
		toUpdate = true
	}
	if toUpdate {
		logger.Debug("UpstreamProvider.Status will be updated", "phase", phase, "message", message)
		if upstream != nil {
			upstreamProvider.Status.EffectiveConfig = upstream.GetEffectiveConfig()
		} else {
			upstreamProvider.Status.EffectiveConfig = nil
		}
		err := r.Status().Update(ctx, upstreamProvider)
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
		logger.Debug("UpstreamProvider.Status is up to date. No update", "phase", phase, "message", message)
	}
	return ctrl.Result{}, nil
}
