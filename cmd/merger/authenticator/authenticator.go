package authenticator

import (
	"context"
	"fmt"
	"kubauth/cmd/merger/config"
	"kubauth/cmd/merger/provider"
	"kubauth/internal/handlers"
	"kubauth/internal/misc"
	"kubauth/internal/proto"
)

type mergerAuthenticator struct {
	providers []provider.Provider
}

var _ handlers.Authenticator = &mergerAuthenticator{}

func New(config *config.Config) (handlers.Authenticator, error) {
	merger := &mergerAuthenticator{}
	merger.providers = make([]provider.Provider, len(config.Providers))
	for i, p := range config.Providers {
		var err error
		merger.providers[i], err = provider.New(p)
		if err != nil {
			return nil, fmt.Errorf("unable to setup provider '%s': %w", p.Name, err)
		}
	}
	return merger, nil
}

func (m *mergerAuthenticator) Authenticate(ctx context.Context, request *proto.IdentityRequest) (*proto.IdentityResponse, error) {
	response := &proto.IdentityResponse{
		User:      proto.InitUser(request.Login),
		Status:    proto.UserNotFound,
		Details:   make([]*proto.UserDetail, len(m.providers)),
		Authority: "",
	}
	for idx, aProvider := range m.providers {
		userDetail, err := aProvider.GetUserDetail(ctx, request.Login, request.Password)
		if err != nil {
			// If provider is not critical, we do not land here. (A UserDetail with Status==Undefined is returned)
			// Error logging and formatting has been performed by caller
			return nil, err
		}
		if !userDetail.Provider.CredentialAuthority && priority(userDetail.Status) > priority(proto.PasswordMissing) {
			// A non-authority provider can't check a password or disable a user
			userDetail.Status = proto.PasswordMissing
		}
		if priority(userDetail.Status) > priority(response.Status) {
			response.Status = userDetail.Status
			if priority(userDetail.Status) > priority(proto.PasswordMissing) {
				// Uid must be provided by the authority provider who test the password
				response.User.Uid = userDetail.Translated.Uid
				response.Authority = aProvider.GetName()
			}
		}
		// Whatever Status is, provider will return a well formed User. So, we can enrich our user.
		if userDetail.Provider.GroupAuthority {
			response.User.Groups = append(response.User.Groups, userDetail.Translated.Groups...)
		}
		if userDetail.Provider.EmailAuthority {
			response.User.Emails = misc.AppendIfNotPresent(response.User.Emails, userDetail.User.Emails)
		}
		if userDetail.Provider.NameAuthority && response.User.Name == "" {
			response.User.Name = userDetail.User.Name
		}
		if userDetail.Provider.ClaimAuthority {
			claims := misc.MergeMaps(userDetail.User.Claims, response.User.Claims)
			response.User.Claims = claims
		}
		response.Details[idx] = userDetail
	}
	response.User.Groups = misc.DedupAndSort(response.User.Groups)

	return response, nil
}

var priorityByStatus = map[proto.Status]int{
	proto.Undefined:         0,
	proto.UserNotFound:      1,
	proto.PasswordMissing:   2,
	proto.PasswordUnchecked: 3,
	proto.PasswordChecked:   4,
	proto.PasswordFail:      4,
	proto.Disabled:          5,
}

func priority(status proto.Status) int {
	return priorityByStatus[status]
}

// Based on comment, complete cmd.merger.authenticator.authenticator.go/appendIfNotPresent function
