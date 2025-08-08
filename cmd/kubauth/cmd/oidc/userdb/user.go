package userdb

import "fmt"

type User struct {
	Login    string
	Password string
	Groups   []string
	Claims   map[string]interface{}
}

type Claim struct {
	Name  string
	Value interface{}
}

type UserDb interface {
	Authenticate(login string, password string) (*User, error)
}

type userDb struct {
	userByLogin map[string]*User
}

var _ UserDb = &userDb{}

func (u *userDb) Authenticate(login string, password string) (*User, error) {
	user, ok := u.userByLogin[login]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	if user.Password != password {
		return nil, fmt.Errorf("invalid password")
	}
	return user, nil
}

func NewUserDb() UserDb {
	db := &userDb{
		userByLogin: make(map[string]*User),
	}
	db.userByLogin["admin"] = &User{
		Login:    "admin",
		Password: "admin123",
		Groups:   []string{"admin"},
	}
	db.userByLogin["sa"] = &User{
		Login:    "sa",
		Password: "sa123",
		Groups:   []string{"admin", "devs"},
		//Claims:   []Claim{{Name: "email", Value: "sa@mycompany.com"}, {Name: "name", Value: "Serge ALEXANDRE"}},
		Claims: map[string]interface{}{
			"email":  "sa@myCompany.com",
			"groups": []string{"admin", "devs"},
			"policy": "myPolicy",
		},
	}

	return db
}
