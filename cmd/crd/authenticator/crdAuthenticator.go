package authenticator

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-logr/logr"
	"golang.org/x/crypto/bcrypt"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"kubauth/internal/handlers"
	"kubauth/internal/misc"
	"kubauth/internal/proto"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sort"
)

type crdAuthenticator struct {
	k8sClient     client.Client
	userNamespace string
}

var _ handlers.Authenticator = &crdAuthenticator{}

func New(k8sClient client.Client, userNamespace string) handlers.Authenticator {
	return &crdAuthenticator{
		k8sClient:     k8sClient,
		userNamespace: userNamespace,
	}
}

func (c *crdAuthenticator) Authenticate(ctx context.Context, request *proto.IdentityRequest) (*proto.IdentityResponse, error) {
	logger := logr.FromContextAsSlogLogger(ctx)

	responsePayload := &proto.IdentityResponse{
		User:      proto.InitUser(request.Login),
		Status:    proto.UserNotFound,
		Details:   nil,
		Authority: "",
	}
	// ------------------- Handle groups (Even if notFound)
	groupBindingList := kubauthv1alpha1.GroupBindingList{}
	err := c.k8sClient.List(ctx, &groupBindingList, client.MatchingFields{"userkey": request.Login}, client.InNamespace(c.userNamespace))
	if err != nil {
		return nil, fmt.Errorf("failed to list groupBindings for user %s: %w", request.Login)
	}
	// Sort groupBindings by group name, to have a predictable claims merge
	sort.Slice(groupBindingList.Items, func(i, j int) bool {
		return groupBindingList.Items[i].Spec.Group < groupBindingList.Items[j].Spec.Group
	})
	if len(groupBindingList.Items) > 0 {
		// Build groups in response and handle claims hosted in groups
		responsePayload.User.Groups = make([]string, 0, len(groupBindingList.Items))
		for _, binding := range groupBindingList.Items {
			responsePayload.User.Groups = append(responsePayload.User.Groups, binding.Spec.Group)
			// Fetch the group if it exists
			group := kubauthv1alpha1.Group{}
			err = c.k8sClient.Get(ctx, client.ObjectKey{Name: binding.Spec.Group, Namespace: c.userNamespace}, &group)
			if client.IgnoreNotFound(err) != nil {
				return nil, fmt.Errorf("error fetching Group %s: %w", binding.Spec.Group, err)
			}
			if err == nil {
				responsePayload.User.Claims, err = merge(responsePayload.User.Claims, group.Spec.Claims) // Users.Claims take precedence
			}
		}
	}
	// Now, try to fetch user
	usr := kubauthv1alpha1.User{}
	err = c.k8sClient.Get(ctx, client.ObjectKey{Namespace: c.userNamespace, Name: request.Login}, &usr)
	if client.IgnoreNotFound(err) != nil {
		return nil, fmt.Errorf("error fetching User '%s': %w", request.Login, err)
	}
	if err != nil {
		logger.Info("User not found", "user", request.Login)
		responsePayload.Status = proto.UserNotFound
		return responsePayload, nil
	}
	if usr.Spec.Uid != nil {
		responsePayload.User.Uid = *usr.Spec.Uid
	}
	responsePayload.User.Name = usr.Spec.Name
	if len(usr.Spec.Emails) > 0 { // Avoid copying a nil
		responsePayload.User.Emails = usr.Spec.Emails
	}
	// --------- Handle claims
	responsePayload.User.Claims, err = merge(responsePayload.User.Claims, usr.Spec.Claims)
	// ----------------------
	if usr.Spec.Disabled != nil && *usr.Spec.Disabled {
		logger.Info("User found but disabled", "user", request.Login)
		responsePayload.Status = proto.Disabled
		return responsePayload, nil
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
	logger.Info("User found", "user", responsePayload.User.Login, "status", responsePayload.Status)
	return responsePayload, nil
}

// addon override base
func merge(a map[string]interface{}, b *apiextensionsv1.JSON) (map[string]interface{}, error) {
	if b == nil {
		return a, nil
	}
	bBis := make(map[string]interface{})
	err := json.Unmarshal(b.Raw, &bBis)
	if err != nil {
		return nil, err
	}
	return misc.MergeMaps(a, bBis), nil
}
