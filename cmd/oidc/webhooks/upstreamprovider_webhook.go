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

package v1alpha1

import (
	"context"
	"strings"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
)

// SetupUpstreamProviderWebhookWithManager registers the webhook for UpstreamProvider in the manager.
func SetupUpstreamProviderWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &kubauthv1alpha1.UpstreamProvider{}).
		WithValidator(&UpstreamProviderCustomValidator{}).
		WithDefaulter(&UpstreamProviderCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-kubauth-kubotal-io-v1alpha1-upstreamprovider,mutating=true,failurePolicy=fail,sideEffects=None,groups=kubauth.kubotal.io,resources=upstreamproviders,verbs=create;update,versions=v1alpha1,name=mupstreamprovider-v1alpha1.kb.io,admissionReviewVersions=v1

// UpstreamProviderCustomDefaulter sets defaults on UpstreamProvider.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type UpstreamProviderCustomDefaulter struct{}

var _ admission.Defaulter[*kubauthv1alpha1.UpstreamProvider] = &UpstreamProviderCustomDefaulter{}

// Default implements admission.Defaulter for UpstreamProvider.
func (d *UpstreamProviderCustomDefaulter) Default(ctx context.Context, u *kubauthv1alpha1.UpstreamProvider) error {
	logger := logr.FromContextAsSlogLogger(ctx)
	if a, ok := u.GetAnnotations()[skipWebhookAnnotation]; ok && strings.ToLower(a) != "no" {
		logger.Info("Skipping defaulting webhook", "kind", u.GetObjectKind().GroupVersionKind().String(), "name", u.GetName(), "namespace", u.GetNamespace())
		return nil
	}

	logger.Debug("Defaulting for UpstreamProvider", "name", u.GetName())

	// TODO: fill in defaulting logic (e.g. mirror valid checks from the reconciler as defaults).

	return nil
}

// +kubebuilder:webhook:path=/validate-kubauth-kubotal-io-v1alpha1-upstreamprovider,mutating=false,failurePolicy=fail,sideEffects=None,groups=kubauth.kubotal.io,resources=upstreamproviders,verbs=create;update,versions=v1alpha1,name=vupstreamprovider-v1alpha1.kb.io,admissionReviewVersions=v1

// UpstreamProviderCustomValidator validates UpstreamProvider on create, update, and delete.
type UpstreamProviderCustomValidator struct{}

var _ admission.Validator[*kubauthv1alpha1.UpstreamProvider] = &UpstreamProviderCustomValidator{}

// ValidateCreate implements admission.Validator for UpstreamProvider.
func (v *UpstreamProviderCustomValidator) ValidateCreate(ctx context.Context, u *kubauthv1alpha1.UpstreamProvider) (admission.Warnings, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Validation for UpstreamProvider upon creation", "name", u.GetName())

	// TODO: fill in validation (e.g. require issuerURL for oidc, mutual exclusivity of configMap vs secret in certificateAuthority, ...).

	return nil, nil
}

// ValidateUpdate implements admission.Validator for UpstreamProvider.
func (v *UpstreamProviderCustomValidator) ValidateUpdate(ctx context.Context, oldU, u *kubauthv1alpha1.UpstreamProvider) (admission.Warnings, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Validation for UpstreamProvider upon update", "name", u.GetName())

	_ = oldU
	// TODO: invariants on spec updates
	return nil, nil
}

// ValidateDelete implements admission.Validator for UpstreamProvider.
func (v *UpstreamProviderCustomValidator) ValidateDelete(ctx context.Context, u *kubauthv1alpha1.UpstreamProvider) (admission.Warnings, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Validation for UpstreamProvider upon deletion", "name", u.GetName())

	// TODO: block delete if needed
	return nil, nil
}
