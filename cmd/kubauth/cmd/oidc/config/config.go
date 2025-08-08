package config

import (
	"kubauth/internal/httpsrv"
)

var Conf = &Config{}

type Config struct {
	HttpConfig httpsrv.Config
	Issuer     string
	Resources  string
}
