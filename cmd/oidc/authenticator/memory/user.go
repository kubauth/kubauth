/*
Copyright (c) 2025 Kubotal.

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

package memory

import (
	"kubauth/cmd/oidc/authenticator"
)

type memoryUser struct {
	Login    string
	Password string
	Claims   map[string]interface{}
}

type userDb struct {
	userByLogin map[string]*memoryUser
}

var _ authenticator.OidcAuthenticator = &userDb{}

func (u *userDb) Authenticate(login string, password string) (*authenticator.OidcUser, error) {
	user, ok := u.userByLogin[login]
	if !ok {
		return nil, nil
	}
	if user.Password != password {
		return nil, nil
	}
	return &authenticator.OidcUser{
		Login:  login,
		Claims: user.Claims,
	}, nil
}

func NewUserDb() authenticator.OidcAuthenticator {
	db := &userDb{
		userByLogin: make(map[string]*memoryUser),
	}
	db.userByLogin["admin"] = &memoryUser{
		Login:    "admin",
		Password: "admin123",
	}
	db.userByLogin["sa"] = &memoryUser{
		Login:    "sa",
		Password: "sa123",
		//Claims:   []Claim{{Name: "email", Value: "sa@mycompany.com"}, {Name: "name", Value: "Serge ALEXANDRE"}},
		Claims: map[string]interface{}{
			"email":  "sa@myCompany.com",
			"groups": []string{"admin", "devs"},
			"policy": "myPolicy",
		},
	}

	return db
}
