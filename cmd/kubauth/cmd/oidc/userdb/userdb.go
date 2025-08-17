package userdb

type User struct {
	Login    string
	Claims   map[string]interface{}
	FullName string
}

type UserDb interface {
	Authenticate(login string, password string) (*User, error)
}
