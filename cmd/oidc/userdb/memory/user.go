package memory

import (
	"kubauth/cmd/oidc/userdb"
)

type memoryUser struct {
	Login    string
	Password string
	Claims   map[string]interface{}
}

type userDb struct {
	userByLogin map[string]*memoryUser
}

var _ userdb.UserDb = &userDb{}

func (u *userDb) Authenticate(login string, password string) (*userdb.User, error) {
	user, ok := u.userByLogin[login]
	if !ok {
		return nil, nil
	}
	if user.Password != password {
		return nil, nil
	}
	return &userdb.User{
		Login:  login,
		Claims: user.Claims,
	}, nil
}

func NewUserDb() userdb.UserDb {
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
