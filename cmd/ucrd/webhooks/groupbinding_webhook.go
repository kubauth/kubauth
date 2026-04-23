/*
Copyright (c) 2025 Kubotal

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

	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
)

// SetupGroupBindingWebhookWithManager registers the webhook for GroupBinding in the manager.
func SetupGroupBindingWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &kubauthv1alpha1.GroupBinding{}).
		WithCustomValidator(&GroupBindingCustomValidator{}).
		WithCustomDefaulter(&GroupBindingCustomDefaulter{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-kubauth-kubotal-io-v1alpha1-groupbinding,mutating=true,failurePolicy=fail,sideEffects=None,groups=kubauth.kubotal.io,resources=groupbindings,verbs=create;update,versions=v1alpha1,name=mgroupbinding-v1alpha1.kb.io,admissionReviewVersions=v1

// GroupBindingCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind GroupBinding when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type GroupBindingCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

var _ webhook.CustomDefaulter = &GroupBindingCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind GroupBinding.
func (d *GroupBindingCustomDefaulter) Default(ctx context.Context, obj runtime.Object) error {
	groupbinding, ok := obj.(*kubauthv1alpha1.GroupBinding)

	if !ok {
		return fmt.Errorf("expected an GroupBinding object but got %T", obj)
	}
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Defaulting for GroupBinding", "name", groupbinding.GetName())

	// TODO(user): fill in your defaulting logic.

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-kubauth-kubotal-io-v1alpha1-groupbinding,mutating=false,failurePolicy=fail,sideEffects=None,groups=kubauth.kubotal.io,resources=groupbindings,verbs=create;update,versions=v1alpha1,name=vgroupbinding-v1alpha1.kb.io,admissionReviewVersions=v1

// GroupBindingCustomValidator struct is responsible for validating the GroupBinding resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type GroupBindingCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &GroupBindingCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type GroupBinding.
func (v *GroupBindingCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	groupbinding, ok := obj.(*kubauthv1alpha1.GroupBinding)
	if !ok {
		return nil, fmt.Errorf("expected a GroupBinding object but got %T", obj)
	}
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Validation for GroupBinding upon creation", "name", groupbinding.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type GroupBinding.
func (v *GroupBindingCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	groupbinding, ok := newObj.(*kubauthv1alpha1.GroupBinding)
	if !ok {
		return nil, fmt.Errorf("expected a GroupBinding object for the newObj but got %T", newObj)
	}
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Validation for GroupBinding upon update", "name", groupbinding.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type GroupBinding.
func (v *GroupBindingCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	groupbinding, ok := obj.(*kubauthv1alpha1.GroupBinding)
	if !ok {
		return nil, fmt.Errorf("expected a GroupBinding object but got %T", obj)
	}
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Validation for GroupBinding upon deletion", "name", groupbinding.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
