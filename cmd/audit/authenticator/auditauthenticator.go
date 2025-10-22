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

type auditAuthenticator struct {
	httpClient httpclient.HttpClient
	k8sClient  client.Client
	namespace  string
}

var _ handlers.Authenticator = &auditAuthenticator{}

func New(config *httpclient.Config, k8sClient client.Client, namespace string) (handlers.Authenticator, error) {
	httpClient, err := httpclient.New(config)
	if err != nil {
		return nil, err
	}
	return &auditAuthenticator{
		httpClient: httpClient,
		k8sClient:  k8sClient,
		namespace:  namespace,
	}, nil
}

// Authenticate Pass through with log
func (l *auditAuthenticator) Authenticate(ctx context.Context, request *proto.IdentityRequest) (*proto.IdentityResponse, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	response := &proto.IdentityResponse{}
	err := proto.Exchange(l.httpClient, "GET", "v1/identity", request, response)
	if err != nil {
		return nil, err
	}
	logger.Info("authenticate", "login", response.User.Login, "status", response.Status, "authority", response.Authority, "groups", response.User.Groups, "claims", response.User.Claims, "emails", response.User.Emails)

	// IA instructions
	// Write a v1alpha1.LoginAttempt record in k8s, fulfilled with 'response' information.
	// record entry name will be with the format <login>-<year>-<month>-<day>-<hour>-<minute>-<second>-<millisecond>
	err = l.createLoginAttemptRecord(ctx, response)
	if err != nil {
		logger.Error("failed to create login record", "error", err)
		// Don't fail the authentication if logging fails
	}

	return response, nil
}

// createLoginAttemptRecord creates a v1alpha1.LoginAttempt record in Kubernetes with the authentication response information
func (l *auditAuthenticator) createLoginAttemptRecord(ctx context.Context, response *proto.IdentityResponse) error {
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

	// Create the LoginAttempt record
	loginRecord := &kubauth.LoginAttempt{
		ObjectMeta: metav1.ObjectMeta{
			Name:      recordName,
			Namespace: l.namespace,
			Labels:    map[string]string{"kubauth.kubotal.io/login": response.User.Login},
		},
		Spec: kubauth.LoginAttemptSpec{
			When:      metav1.NewTime(now),
			Authority: response.Authority,
			Status:    string(response.Status),
			User: kubauth.LoginAttemptUser{
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

// convertDetails converts proto.UserDetail slice to kubauth.LoginAttemptDetail slice
func (l *auditAuthenticator) convertDetails(details []*proto.UserDetail) []kubauth.LoginAttemptDetail {
	if details == nil {
		return nil
	}

	result := make([]kubauth.LoginAttemptDetail, len(details))
	for i, detail := range details {
		// Convert user claims to JSON
		var userClaimsJSON *apiextensionsv1.JSON
		if detail.User.Claims != nil {
			claimsRaw, err := json.Marshal(detail.User.Claims)
			if err == nil {
				userClaimsJSON = &apiextensionsv1.JSON{Raw: claimsRaw}
			}
		}

		// Convert translated claims to JSON
		var translatedClaimsJSON apiextensionsv1.JSON
		if detail.Translated.Claims != nil {
			translatedRaw, err := json.Marshal(detail.Translated.Claims)
			if err == nil {
				translatedClaimsJSON.Raw = translatedRaw
			}
		}

		result[i] = kubauth.LoginAttemptDetail{
			Provider: kubauth.LoginAttemptDetailProvider{
				Name:                detail.Provider.Name,
				ClaimAuthority:      detail.Provider.ClaimAuthority,
				CredentialAuthority: detail.Provider.CredentialAuthority,
				EmailAuthority:      detail.Provider.EmailAuthority,
				GroupAuthority:      detail.Provider.GroupAuthority,
				NameAuthority:       detail.Provider.NameAuthority,
			},
			User: kubauth.LoginAttemptUser{
				Login:  detail.User.Login,
				Uid:    detail.User.Uid,
				Name:   detail.User.Name,
				Emails: detail.User.Emails,
				Groups: detail.User.Groups,
				Claims: userClaimsJSON,
			},
			Status: string(detail.Status),
			Translated: kubauth.LoginAttemptDetailTranslated{
				Claims: translatedClaimsJSON,
				Groups: detail.Translated.Groups,
				Uid:    detail.Translated.Uid,
			},
		}
	}

	return result
}
