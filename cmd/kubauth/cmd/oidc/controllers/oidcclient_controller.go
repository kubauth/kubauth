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

package kubauthmodel

import (
	"context"
	"github.com/ory/fosite"
	"k8s.io/apimachinery/pkg/runtime"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"kubauth/cmd/kubauth/cmd/oidc/fositeclient"
	"kubauth/cmd/kubauth/cmd/oidc/oidcstorage"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// OidcClientReconciler reconciles a OidcClient object
type OidcClientReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Namespace string // Where OidcClient are stored
	Storage   *oidcstorage.MemoryStore
}

// +kubebuilder:rbac:groups=kubauth.kubotal.io,resources=oidcclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kubauth.kubotal.io,resources=oidcclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kubauth.kubotal.io,resources=oidcclients/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the OidcClient object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *OidcClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// _ = logf.FromContext(ctx)

	// We don't care about who trigger this. We fetch all clients which are in our namespace and store them in configStore
	clients := &kubauthv1alpha1.OidcClientList{}
	err := r.List(ctx, clients, client.InNamespace(r.Namespace))
	if err != nil {
		return ctrl.Result{}, err
	}

	fositeClients := make(map[string]fosite.Client)
	for idx, _ := range clients.Items {
		fositeClients[clients.Items[idx].Spec.Id] = fositeclient.NewFositeClient(&clients.Items[idx].Spec)
	}
	r.Storage.SetClients(ctx, fositeClients)

	return ctrl.Result{}, nil
}
