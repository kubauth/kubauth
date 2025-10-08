/*
Copyright (c) Kubotal 2025.

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

package authenticator

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"gopkg.in/ldap.v2"
	"kubauth/cmd/ldap/config"
	"kubauth/internal/handlers"
	"kubauth/internal/misc"
	"os"
	"time"
)

type ldapAuthenticator struct {
	config           *config.LdapConfig
	hostPort         string // Built from config
	tlsConfig        *tls.Config
	userSearchScope  int
	groupSearchScope int
}

var _ handlers.Authenticator = &ldapAuthenticator{}

func New(ldapConfig *config.LdapConfig, configFolder string) (handlers.Authenticator, error) {

	authenticator := ldapAuthenticator{
		config: ldapConfig,
	}
	if authenticator.config.Host == "" {
		return &authenticator, fmt.Errorf("missing required ldap.host")
	}
	if authenticator.config.UserSearch.BaseDN == "" {
		return &authenticator, fmt.Errorf("missing required ldap.userSearch.baseDN")
	}
	if authenticator.config.UserSearch.LoginAttr == "" {
		return &authenticator, fmt.Errorf("missing required ldap.userSearch.loginAttr")
	}
	if authenticator.config.GroupSearch.BaseDN != "" {
		if authenticator.config.GroupSearch.BaseDN == "" {
			return &authenticator, fmt.Errorf("missing required ldap.groupSearch.baseDN")
		}
		if authenticator.config.GroupSearch.NameAttr == "" {
			return &authenticator, fmt.Errorf("missing required ldap.groupSearch.nameAttr")
		}
		if authenticator.config.GroupSearch.LinkGroupAttr == "" {
			return &authenticator, fmt.Errorf("missing required ldap.groupSearch.linkGroupAttr")
		}
		if authenticator.config.GroupSearch.LinkUserAttr == "" {
			return &authenticator, fmt.Errorf("missing required ldap.groupSearch.linkUserAttr")
		}
	}
	// Setup default value
	if authenticator.config.Port == "" {
		if authenticator.config.InsecureNoSSL {
			authenticator.config.Port = "389"
		} else {
			authenticator.config.Port = "636"
		}
	}
	authenticator.hostPort = fmt.Sprintf("%s:%s", authenticator.config.Host, authenticator.config.Port)
	if authenticator.config.TimeoutSec == 0 {
		authenticator.config.TimeoutSec = 10
	}
	// WARNING: This is a global variable
	ldap.DefaultTimeout = time.Duration(authenticator.config.TimeoutSec) * time.Second

	//authenticator.logger.V(2).Info("paths", "configFolder", configFolder, "RootCA", authenticator.RootCaPath, "ClientCert", authenticator.ClientCert, "ClientKey", authenticator.ClientKey)
	authenticator.config.RootCaPath = misc.AdjustPath(configFolder, authenticator.config.RootCaPath)
	authenticator.config.ClientCert = misc.AdjustPath(configFolder, authenticator.config.ClientCert)
	authenticator.config.ClientKey = misc.AdjustPath(configFolder, authenticator.config.ClientKey)
	//authenticator.logger.V(2).Info("adjusted paths", "RootCA", authenticator.RootCaPath, "ClientCert", authenticator.ClientCert, "ClientKey", authenticator.ClientKey)

	authenticator.tlsConfig = &tls.Config{ServerName: authenticator.config.Host, InsecureSkipVerify: authenticator.config.InsecureSkipVerify}
	if authenticator.config.RootCaPath != "" || len(authenticator.config.RootCaData) != 0 {
		var data []byte
		if len(authenticator.config.RootCaData) != 0 {
			data = make([]byte, base64.StdEncoding.DecodedLen(len(authenticator.config.RootCaData)))
			_, err := base64.StdEncoding.Decode(data, []byte(authenticator.config.RootCaData))
			if err != nil {
				return &authenticator, fmt.Errorf("error while parsing RootCaData : %w", err)
			}
		} else {
			var err error
			if data, err = os.ReadFile(authenticator.config.RootCaPath); err != nil {
				return &authenticator, fmt.Errorf("error while reading CA file: %w", err)
			}
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(data) {
			return &authenticator, fmt.Errorf("no certs found in ca file")
		}
		authenticator.tlsConfig.RootCAs = rootCAs
	}

	if authenticator.config.ClientKey != "" && authenticator.config.ClientCert != "" {
		cert, err := tls.LoadX509KeyPair(authenticator.config.ClientCert, authenticator.config.ClientKey)
		if err != nil {
			return &authenticator, fmt.Errorf("load client cert failed: %v", err)
		}
		authenticator.tlsConfig.Certificates = append(authenticator.tlsConfig.Certificates, cert)
	}
	var ok bool
	authenticator.userSearchScope, ok = parseScope(authenticator.config.UserSearch.Scope)
	if !ok {
		return &authenticator, fmt.Errorf("userSearch.Scope unknown value %q", authenticator.config.UserSearch.Scope)
	}
	authenticator.groupSearchScope, ok = parseScope(authenticator.config.GroupSearch.Scope)
	if !ok {
		return &authenticator, fmt.Errorf("groupSearch.Scope unknown value %q", authenticator.config.GroupSearch.Scope)
	}
	return &authenticator, nil
}

func parseScope(s string) (int, bool) {
	// NOTE(ericchiang): ScopeBaseObject doesn't really make sense for us because we
	// never know the user's or group's DN.
	switch s {
	case "", "sub":
		return ldap.ScopeWholeSubtree, true
	case "one":
		return ldap.ScopeSingleLevel, true
	}
	return 0, false
}
