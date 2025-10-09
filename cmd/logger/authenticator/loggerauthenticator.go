package authenticator

import (
	"context"
	"github.com/go-logr/logr"
	"kubauth/internal/handlers"
	"kubauth/internal/httpclient"
	"kubauth/internal/proto"
)

type loggerAuthenticator struct {
	httpClient httpclient.HttpClient
}

var _ handlers.Authenticator = &loggerAuthenticator{}

func New(config *httpclient.Config) (handlers.Authenticator, error) {
	httpClient, err := httpclient.New(config)
	if err != nil {
		return nil, err
	}
	return &loggerAuthenticator{
		httpClient: httpClient,
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
	return response, nil
}
