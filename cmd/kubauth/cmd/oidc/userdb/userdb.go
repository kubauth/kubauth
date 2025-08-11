package userdb

type User struct {
	Login  string
	Claims map[string]interface{}
}

type UserDb interface {
	Authenticate(login string, password string) (*User, error)
}
