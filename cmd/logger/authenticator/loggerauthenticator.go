package authenticator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubauth "kubauth/api/kubauth/v1alpha1"
	"kubauth/internal/handlers"
	"kubauth/internal/httpclient"
	"kubauth/internal/proto"
)

type loggerAuthenticator struct {
	httpClient httpclient.HttpClient
	k8sClient  client.Client
	namespace  string
}

var _ handlers.Authenticator = &loggerAuthenticator{}

func New(config *httpclient.Config, k8sClient client.Client, namespace string) (handlers.Authenticator, error) {
	httpClient, err := httpclient.New(config)
	if err != nil {
		return nil, err
	}
	return &loggerAuthenticator{
		httpClient: httpClient,
		k8sClient:  k8sClient,
		namespace:  namespace,
	}, nil
}

// Authenticate Pass through with log
func (l *loggerAuthenticator) Authenticate(ctx context.Context, request *proto.IdentityRequest) (*proto.IdentityResponse, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	response := &proto.IdentityResponse{}
	err := proto.Exchange(l.httpClient, "GET", "v1/identity", request, response)
	if err != nil {
		return nil, err
	}
	logger.Info("authenticate", "login", response.User.Login, "status", response.Status, "authority", response.Authority, "groups", response.User.Groups, "claims", response.User.Claims, "emails", response.User.Emails)

	// IA instructions
	// Write a v1alpha1.Login record in k8s, fulfilled with 'response' information.
	// record entry name will be with the format <login>-<year>-<month>-<day>-<hour>-<minute>-<second>-<millisecond>
	err = l.createLoginRecord(ctx, response)
	if err != nil {
		logger.Error("failed to create login record", "error", err)
		// Don't fail the authentication if logging fails
	}

	return response, nil
}

// createLoginRecord creates a v1alpha1.Login record in Kubernetes with the authentication response information
func (l *loggerAuthenticator) createLoginRecord(ctx context.Context, response *proto.IdentityResponse) error {
	now := time.Now()

	// Generate record name with format: <login>-<year>-<month>-<day>-<hour>-<minute>-<second>-<millisecond>
	recordName := fmt.Sprintf("%s-%04d-%02d-%02d-%02d-%02d-%02d-%03d",
		response.User.Login,
		now.Year(),
		now.Month(),
		now.Day(),
		now.Hour(),
		now.Minute(),
		now.Second(),
		now.Nanosecond()/1000000, // Convert nanoseconds to milliseconds
	)

	// Convert claims to JSON if present
	var claimsJSON *apiextensionsv1.JSON
	if response.User.Claims != nil {
		claimsRaw, err := json.Marshal(response.User.Claims)
		if err == nil {
			claimsJSON = &apiextensionsv1.JSON{Raw: claimsRaw}
		}
	}

	// Create the Login record
	loginRecord := &kubauth.Login{
		ObjectMeta: metav1.ObjectMeta{
			Name:      recordName,
			Namespace: l.namespace,
		},
		Spec: kubauth.LoginSpec{
			When:      metav1.NewTime(now),
			Authority: response.Authority,
			Status:    string(response.Status),
			User: kubauth.LoginUser{
				Login:  response.User.Login,
				Uid:    response.User.Uid,
				Name:   response.User.Name,
				Emails: response.User.Emails,
				Groups: response.User.Groups,
				Claims: claimsJSON,
			},
			Details: l.convertDetails(response.Details),
		},
	}

	// Create the record in Kubernetes
	return l.k8sClient.Create(ctx, loginRecord)
}

// convertDetails converts proto.UserDetail slice to kubauth.LoginDetail slice
func (l *loggerAuthenticator) convertDetails(details []*proto.UserDetail) []kubauth.LoginDetail {
	if details == nil {
		return nil
	}

	result := make([]kubauth.LoginDetail, len(details))
	for i, detail := range details {
		// Convert claims to JSON
		var claimsJSON apiextensionsv1.JSON
		var userClaimsJSON *apiextensionsv1.JSON
		if detail.User.Claims != nil {
			claimsRaw, err := json.Marshal(detail.User.Claims)
			if err == nil {
				claimsJSON.Raw = claimsRaw
				userClaimsJSON = &apiextensionsv1.JSON{Raw: claimsRaw}
			}
		}

		result[i] = kubauth.LoginDetail{
			Provider: kubauth.LoginDetailProvider{
				Name:                detail.Provider.Name,
				ClaimAuthority:      detail.Provider.ClaimAuthority,
				CredentialAuthority: detail.Provider.CredentialAuthority,
				EmailAuthority:      detail.Provider.EmailAuthority,
				GroupAuthority:      detail.Provider.GroupAuthority,
				NameAuthority:       detail.Provider.NameAuthority,
			},
			User: kubauth.LoginUser{
				Login:  detail.User.Login,
				Uid:    detail.User.Uid,
				Name:   detail.User.Name,
				Emails: detail.User.Emails,
				Groups: detail.User.Groups,
				Claims: userClaimsJSON,
			},
			Status: string(detail.Status),
			Translated: kubauth.LoginDetailTranslated{
				Claims: claimsJSON,
				Groups: detail.Translated.Groups,
				Uid:    detail.Translated.Uid,
			},
		}
	}

	return result
}

/*
	There is a bug here. detail.Translated.Claims is set with non-translated values.

*/
