package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-logr/logr"
	"golang.org/x/crypto/bcrypt"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"kubauth/cmd/kubauth/proto"
	"kubauth/internal/misc"
	"net/http"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sort"
)

func IdentityHandler(k8sClient client.Client, userNamespace string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := logr.FromContextAsSlogLogger(ctx)

		var requestPayload proto.IdentityRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&requestPayload)
		if err != nil {
			logger.Error("error decoding identity request", "error", err)
			http.Error(w, fmt.Sprintf("Payload decoding: %v", err), http.StatusBadRequest)
			return
		}
		if requestPayload.Detailed {
			logger.Error("Can't handle detailed identity request")
			http.Error(w, fmt.Sprintf("Can't handle detailed identity request"), http.StatusBadRequest)
			return
		}
		responsePayload, err, errorContext := getIdentity(ctx, requestPayload, k8sClient, userNamespace)
		if err != nil {
			logger.Error(errorContext, "error", err)
			http.Error(w, fmt.Sprintf("%s: %v", errorContext, err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(responsePayload)
		if err != nil {
			panic(err)
		}
	})
}

func getIdentity(ctx context.Context, request proto.IdentityRequest, k8sClient client.Client, userNamespace string) (*proto.IdentityResponse, error, string) {
	logger := logr.FromContextAsSlogLogger(ctx)

	responsePayload := &proto.IdentityResponse{
		Status:    proto.UserNotFound,
		User:      proto.InitUser(request.Login),
		Details:   []proto.UserDetail{},
		Authority: "",
	}
	// ------------------- Handle groups (Even if notFound)
	list := kubauthv1alpha1.GroupBindingList{}
	err := k8sClient.List(ctx, &list, client.MatchingFields{"userkey": request.Login}, client.InNamespace(userNamespace))
	if err != nil {
		return nil, err, "error fetching GroupBindings"
	}
	// Sort groupBindings by group name, to have a predictable claims merge
	sort.Slice(list.Items, func(i, j int) bool {
		return list.Items[i].Spec.Group < list.Items[j].Spec.Group
	})
	if len(list.Items) > 0 {
		// First, create implicit claim 'group'
		groupsClaims := make([]string, len(list.Items))
		for idx, binding := range list.Items {
			groupsClaims[idx] = binding.Spec.Group
		}
		responsePayload.Claims = map[string]interface{}{"groups": groupsClaims}
		// Now, handle claims hosted in groups
		responsePayload.Groups = make([]string, 0, len(list.Items))
		for _, binding := range list.Items {
			responsePayload.Groups = append(responsePayload.Groups, binding.Spec.Group)
			// Fetch the group if it exists
			group := kubauthv1alpha1.Group{}
			err = k8sClient.Get(ctx, client.ObjectKey{Name: binding.Spec.Group, Namespace: userNamespace}, &group)
			if client.IgnoreNotFound(err) != nil {
				return nil, err, fmt.Sprintf("error fetching Group %s", binding.Spec.Group)
			}
			if err == nil {
				responsePayload.Claims, err = merge(responsePayload.Claims, group.Spec.Claims)
			}
		}
	}
	// Now, try to fetch user
	usr := kubauthv1alpha1.User{}
	err = k8sClient.Get(ctx, client.ObjectKey{Namespace: userNamespace, Name: request.Login}, &usr)
	if client.IgnoreNotFound(err) != nil {
		return nil, err, fmt.Sprintf("error fetching User '%s'", request.Login)
	}
	if err != nil {
		logger.Info("User not found", "user", request.Login)
		responsePayload.Status = proto.UserNotFound
		return responsePayload, nil, ""
	}
	if usr.Spec.Uid != nil {
		responsePayload.Uid = *usr.Spec.Uid
	}
	if len(usr.Spec.CommonNames) > 0 { // Avoid copying a nil
		responsePayload.CommonNames = usr.Spec.CommonNames
		responsePayload.Claims["name"] = usr.Spec.CommonNames[0]
	}
	if len(usr.Spec.Emails) > 0 { // Avoid copying a nil
		responsePayload.Emails = usr.Spec.Emails
		responsePayload.Claims["email"] = usr.Spec.Emails[0]
	}
	// --------- Handle claims
	responsePayload.Claims, err = merge(responsePayload.Claims, usr.Spec.Claims)
	// ----------------------
	if usr.Spec.Disabled != nil && *usr.Spec.Disabled {
		logger.Info("User found but disabled", "user", request.Login)
		responsePayload.Status = proto.Disabled
		return responsePayload, nil, ""
	}
	if usr.Spec.PasswordHash == "" {
		responsePayload.Status = proto.PasswordMissing
	} else if request.Password == "" {
		responsePayload.Status = proto.PasswordUnchecked
	} else {
		err := bcrypt.CompareHashAndPassword([]byte(usr.Spec.PasswordHash), []byte(request.Password))
		if err == nil {
			responsePayload.Status = proto.PasswordChecked
		} else {
			responsePayload.Status = proto.PasswordFail
		}
	}
	logger.Info("User found", "user", responsePayload.Login, "status", responsePayload.Status)
	return responsePayload, nil, ""
}

func merge(base map[string]interface{}, addon *apiextensionsv1.JSON) (map[string]interface{}, error) {
	if addon == nil {
		return base, nil
	}
	inc := make(map[string]interface{})
	err := json.Unmarshal(addon.Raw, &inc)
	if err != nil {
		return nil, err
	}
	return misc.MergeMaps(base, inc), nil
}
