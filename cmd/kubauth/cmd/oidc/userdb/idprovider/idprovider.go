package idprovider

import (
	"kubauth/cmd/kubauth/cmd/oidc/userdb"
	"kubauth/cmd/kubauth/proto"
	"kubauth/internal/httpclient"
)

type idProvider struct {
	httpClient httpclient.HttpClient
}

var _ userdb.UserDb = &idProvider{}

func New(config *httpclient.Config) (userdb.UserDb, error) {
	httpClient, err := httpclient.New(config)
	if err != nil {
		return nil, err
	}
	idp := &idProvider{
		httpClient: httpClient,
	}
	return idp, nil
}

func (u *idProvider) Authenticate(login string, password string) (*userdb.User, error) {
	request := &proto.IdentityRequest{
		Login:    login,
		Password: password,
		Detailed: false,
	}
	response := &proto.IdentityResponse{}
	err := u.httpClient.Do("GET", "v1/identity", request, response)
	if err != nil {
		return nil, err
	}
	if response.Status != proto.PasswordChecked {
		return nil, nil
	}
	fullName := ""
	if len(response.CommonNames) > 0 {
		fullName = response.CommonNames[0]
	}
	return &userdb.User{
		Login:    login,
		Claims:   response.Claims,
		FullName: fullName,
	}, nil
}
