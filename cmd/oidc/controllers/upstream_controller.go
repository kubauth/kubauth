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
	"encoding/base64"
	"fmt"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"kubauth/cmd/oidc/oidcstorage"
	"kubauth/cmd/oidc/upstreams"
	"log/slog"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const defaultUpstreamCAKey = "ca.crt"

// +kubebuilder:rbac:groups=kubauth.kubotal.io,resources=upstreamproviders,verbs=get;list;watch;patch;update
// +kubebuilder:rbac:groups=kubauth.kubotal.io,resources=upstreamproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// UpstreamProviderReconciler reconciles a UpstreamProvider object
type UpstreamProviderReconciler struct {
	client.Client
	record.EventRecorder
	Scheme           *runtime.Scheme
	Storage          *oidcstorage.MemoryStore
	statusErrorCount int
	Logger           *slog.Logger
}

// Reconcile
// Note about retry on error: As most of error are releated to wrong input parameters, we don't need to retry, as fixing the error will be performed by re-applying the object.
// An exception is the configuration discovery. We can retry waiting for the upstream server up
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
		// Only Ready upstreams are registered in storage
		if upstreamProvider.Status.Phase == kubauthv1alpha1.UpstreamProviderPhaseReady {
			r.Storage.DeleteUpstream(ctx, upstreams.BuildUpstreamId(upstreamProvider.Name, upstreamProvider.Namespace))
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
		r.Storage.SetUpstream(ctx, upstream)
		r.Event(upstreamProvider, "Normal", "Created", "Created internal upstream")
		return r.updateStatus(ctx, upstreamProvider, upstream, nil)
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
		if spec.ExplicitConfig != nil && spec.ExplicitConfig.AuthURL == "" {
			return fmt.Errorf("upstream provider explicitConfig has no authURL")
		}
		return nil
	}()
	if err != nil {
		r.Event(upstreamProvider, "Warning", "Configuration", err.Error())
		return r.updateStatus(ctx, upstreamProvider, nil, err)
	}

	clientSecret := ""
	if upstreamProvider.Spec.ClientSecret != nil {
		var secErr error
		clientSecret, secErr = r.fetchClientSecret(ctx, req.Namespace, upstreamProvider.Spec.ClientSecret)
		if secErr != nil {
			r.Event(upstreamProvider, "Warning", "Configuration", secErr.Error())
			return r.updateStatus(ctx, upstreamProvider, nil, secErr)
		}
	}

	caData := ""
	if upstreamProvider.Spec.CertificateAuthority != nil {
		var caErr error
		caData, caErr = r.fetchCertificateAuthority(ctx, req.Namespace, upstreamProvider.Spec.CertificateAuthority)
		if caErr != nil {
			r.Event(upstreamProvider, "Warning", "Configuration", caErr.Error())
			return r.updateStatus(ctx, upstreamProvider, nil, caErr)
		}
	}

	upstream, err := upstreams.NewUpstream(ctx, upstreamProvider, clientSecret, caData)
	if err != nil {
		r2, err2 := r.updateStatus(ctx, upstreamProvider, upstream, err)
		if err2 != nil {
			return r2, err2
		}
		r.Event(upstreamProvider, "Warning", "CreationFailure", err.Error())
		return ctrl.Result{}, err // Event if updateStatus is successful, we enter the retry loop, waiting for upstream oidc server ready
	}
	r.Event(upstreamProvider, "Normal", "Created", "Created upstream OIDC server")
	r.Storage.SetUpstream(ctx, upstream)
	return r.updateStatus(ctx, upstreamProvider, upstream, err)
}

func (r *UpstreamProviderReconciler) updateStatus(ctx context.Context, upstreamProvider *kubauthv1alpha1.UpstreamProvider, upstream upstreams.Upstream, err error) (ctrl.Result, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	message := "OK"
	phase := kubauthv1alpha1.UpstreamProviderPhaseReady
	if err != nil {
		message = err.Error()
		phase = kubauthv1alpha1.UpstreamProviderPhaseError
		logger.Error("UpstreamProvider.Status updated in error", "phase", phase, "message", message)
	} else {
		logger.Debug("UpstreamProvider.Status will be updated", "phase", phase, "message", message)
	}
	upstreamProvider.Status.Phase = phase
	upstreamProvider.Status.Message = message
	if upstream != nil {
		upstreamProvider.Status.EffectiveConfig = upstream.GetEffectiveConfig()
	} else {
		upstreamProvider.Status.EffectiveConfig = nil
	}
	err = r.Status().Update(ctx, upstreamProvider)
	if err != nil {
		if r.statusErrorCount == 0 {
			// If this is the first error, don't use the usual CrashLoopBackOff, but retry
			r.statusErrorCount++
			logger.Debug("Error updating status. Hidden as first one", "phase", phase)
			return ctrl.Result{RequeueAfter: time.Millisecond * 200}, nil
		}
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *UpstreamProviderReconciler) fetchClientSecret(ctx context.Context, namespace string, src *kubauthv1alpha1.LocalSecretReference) (string, error) {
	if src == nil || src.Secret.Name == "" {
		return "", fmt.Errorf("clientSecret.secret name is required")
	}
	if src.Secret.Key == "" {
		return "", fmt.Errorf("clientSecret.key is required")
	}
	var secret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: src.Secret.Name}, &secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("client secret %q not found in namespace %q", src.Secret.Name, namespace)
		}
		return "", err
	}
	value, ok := secret.Data[src.Secret.Key]
	if !ok {
		return "", fmt.Errorf("no key %q in secret %q/%q", src.Secret.Key, namespace, src.Secret.Name)
	}
	return string(value), nil
}

// Return the CA encoded in base64
func (r *UpstreamProviderReconciler) fetchCertificateAuthority(ctx context.Context, namespace string, src *kubauthv1alpha1.CertificateAuthoritySource) (string, error) {
	hasCM := src.ConfigMap != nil && src.ConfigMap.Name != ""
	hasSec := src.Secret != nil && src.Secret.Name != ""
	if hasCM && hasSec {
		return "", fmt.Errorf("certificateAuthority: set only one of configMap or secret")
	}
	if !hasCM && !hasSec {
		return "", fmt.Errorf("certificateAuthority: one of configMap or secret is required")
	}
	if hasCM {
		// ------------------------------- CA in configMap
		key := src.ConfigMap.Key
		if key == "" {
			key = defaultUpstreamCAKey
		}
		var cm corev1.ConfigMap
		err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: src.ConfigMap.Name}, &cm)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return "", fmt.Errorf("certificate authority configMap %q not found in namespace %q", src.ConfigMap.Name, namespace)
			}
			return "", err
		}
		value, ok := cm.Data[key]
		if !ok {
			return "", fmt.Errorf("no key %q in configmap %q/%q", key, namespace, src.ConfigMap.Name)
		}
		return base64.StdEncoding.EncodeToString([]byte(value)), nil
	}
	// ----------------------------------- CA in secret
	key := src.Secret.Key
	if key == "" {
		key = defaultUpstreamCAKey
	}
	var secret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: src.Secret.Name}, &secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("certificate authority secret %q not found in namespace %q", src.Secret.Name, namespace)
		}
		return "", err
	}
	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("no key %q in secret %q/%q", key, namespace, src.Secret.Name)
	}
	return base64.StdEncoding.EncodeToString(value), nil
}
