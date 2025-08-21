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

package v1alpha1

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	kubautv1alpha1 "kubauth/api/kubauth/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
// var oidcclientlog = logf.Log.WithName("oidcclient-resource")

// SetupOidcClientWebhookWithManager registers the webhook for OidcClient in the manager.
func SetupOidcClientWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&kubautv1alpha1.OidcClient{}).
		WithValidator(&OidcClientCustomValidator{}).
		WithDefaulter(&OidcClientCustomDefaulter{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-kubauth-kubotal-io-v1alpha1-oidcclient,mutating=true,failurePolicy=fail,sideEffects=None,groups=kubauth.kubotal.io,resources=oidcclients,verbs=create;update,versions=v1alpha1,name=moidcclient-v1alpha1.kb.io,admissionReviewVersions=v1

// OidcClientCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind OidcClient when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type OidcClientCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

var _ webhook.CustomDefaulter = &OidcClientCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind OidcClient.
func (d *OidcClientCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	oidcclient, ok := obj.(*kubautv1alpha1.OidcClient)

	if !ok {
		return fmt.Errorf("expected an OidcClient object but got %T", obj)
	}
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Defaulting for OidcClient", "name", oidcclient.GetName())

	// TODO(user): fill in your defaulting logic.

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-kubauth-kubotal-io-v1alpha1-oidcclient,mutating=false,failurePolicy=fail,sideEffects=None,groups=kubauth.kubotal.io,resources=oidcclients,verbs=create;update,versions=v1alpha1,name=voidcclient-v1alpha1.kb.io,admissionReviewVersions=v1

// OidcClientCustomValidator struct is responsible for validating the OidcClient resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type OidcClientCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &OidcClientCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type OidcClient.
func (v *OidcClientCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	oidcclient, ok := obj.(*kubautv1alpha1.OidcClient)
	if !ok {
		return nil, fmt.Errorf("expected a OidcClient object but got %T", obj)
	}
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Validation for OidcClient upon creation", "name", oidcclient.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type OidcClient.
func (v *OidcClientCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oidcclient, ok := newObj.(*kubautv1alpha1.OidcClient)
	if !ok {
		return nil, fmt.Errorf("expected a OidcClient object for the newObj but got %T", newObj)
	}
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Validation for OidcClient upon update", "name", oidcclient.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type OidcClient.
func (v *OidcClientCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	oidcclient, ok := obj.(*kubautv1alpha1.OidcClient)
	if !ok {
		return nil, fmt.Errorf("expected a OidcClient object but got %T", obj)
	}
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Validation for OidcClient upon deletion", "name", oidcclient.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
