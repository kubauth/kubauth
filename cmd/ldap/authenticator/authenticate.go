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
	"context"
	"fmt"
	"kubauth/internal/proto"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-logr/logr"
)

// NB: This code is strongly inspired from dex idp  (https://github.com/dexidp/dex)

func (l *ldapAuthenticator) Authenticate(ctx context.Context, request *proto.IdentityRequest) (*proto.IdentityResponse, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	// Set some default values
	response := proto.IdentityResponse{
		User:      proto.InitUser(request.Login),
		Status:    proto.UserNotFound,
		Details:   nil,
		Authority: "",
	}
	var ldapUser *ldap.Entry
	err := l.do(ctx, func(conn *ldap.Conn) error {
		var err error
		bindDesc := fmt.Sprintf("conn.Bind(%s, %s)", l.config.BindDN, "xxxxxxxx")
		if err = serviceBind(conn, l.config.BindDN, l.config.BindPW); err != nil {
			return fmt.Errorf("%s failed: %v", bindDesc, err)
		}
		logger.Debug(fmt.Sprintf("%s => success", bindDesc))
		if ldapUser, err = l.lookupUser(ctx, conn, request.Login); err != nil {
			return err
		}
		if ldapUser != nil {
			if request.Password != "" {
				if response.Status, err = l.checkPassword(ctx, conn, *ldapUser, request.Password); err != nil {
					return err
				}
			} else {
				response.Status = proto.PasswordUnchecked
			}
			// We need to bind again, as password check was performed on user
			bindDesc := fmt.Sprintf("conn.Bind(%s, %s)", l.config.BindDN, "xxxxxxxx")
			if err := serviceBind(conn, l.config.BindDN, l.config.BindPW); err != nil {
				return fmt.Errorf("%s failed: %v", bindDesc, err)
			}
			logger.Debug(fmt.Sprintf("%s => success", bindDesc), "bindDesc", bindDesc)
			if response.User.Groups, err = l.lookupGroups(ctx, conn, *ldapUser); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if ldapUser != nil {
		logger.Debug("Will fetch Attributes")
		uidStr := getAttr(*ldapUser, l.config.UserSearch.NumericalIdAttr)
		if uidStr != "" {
			uid, err := strconv.Atoi(uidStr)
			if err != nil {
				logger.Error("Non numerical Uid value", "uidStr", uidStr, "login", request.Login, "error", err)
			}
			response.User.Uid = &uid
		}
		response.User.Emails = getAttrs(*ldapUser, l.config.UserSearch.EmailAttr)
		response.User.Name = getAttr(*ldapUser, l.config.UserSearch.CnAttr)
		logger.Info("User found", "login", response.User.Login, "status", response.Status, "groups", response.User.Groups, "claims", response.User.Claims, "emails", response.User.Emails)
	} else {
		logger.Info("User not found", "login", request.Login)
	}

	return &response, nil
}

// do() initializes a connection to the LDAP directory and passes it to the
// provided function. It then performs appropriate teardown or reuse before
// returning.
func (l *ldapAuthenticator) do(ctx context.Context, f func(c *ldap.Conn) error) error {
	logger := logr.FromContextAsSlogLogger(ctx)
	var (
		conn *ldap.Conn
		err  error
	)
	switch {
	case l.config.InsecureNoSSL:
		logger.Debug("Dial('tcp')", "hostPort", l.hostPort)
		conn, err = ldap.Dial("tcp", l.hostPort)
	case l.config.StartTLS:
		logger.Debug("Dial('tcp'", "hostPort", l.hostPort)
		conn, err = ldap.Dial("tcp", l.hostPort)
		if err != nil {
			return fmt.Errorf("failed to connect: %v", err)
		}
		logger.Debug("conn.StartTLS(tlsConfig")
		if err := conn.StartTLS(l.tlsConfig); err != nil {
			return fmt.Errorf("start TLS failed: %v", err)
		}
	default:
		logger.Debug("DialTLS('tcp', tlsConfig)", "hostPort", l.hostPort)
		conn, err = ldap.DialTLS("tcp", l.hostPort, l.tlsConfig)
	}
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer func() {
		logger.Debug("Closing ldap connection")
		conn.Close()
	}()
	return f(conn)
}

func (l *ldapAuthenticator) lookupUser(ctx context.Context, conn *ldap.Conn, login string) (*ldap.Entry, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	filter := fmt.Sprintf("(%s=%s)", l.config.UserSearch.LoginAttr, ldap.EscapeFilter(login))
	if l.config.UserSearch.Filter != "" {
		filter = fmt.Sprintf("(&%s%s)", l.config.UserSearch.Filter, filter)
	}
	// Initial search.
	req := &ldap.SearchRequest{
		BaseDN: l.config.UserSearch.BaseDN,
		Filter: filter,
		Scope:  l.userSearchScope,
		// We only need to search for these specific requests.
		Attributes: []string{
			l.config.UserSearch.LoginAttr,
		},
	}
	if l.config.UserSearch.NumericalIdAttr != "" {
		req.Attributes = append(req.Attributes, l.config.UserSearch.NumericalIdAttr)
	}
	if l.config.UserSearch.EmailAttr != "" {
		req.Attributes = append(req.Attributes, l.config.UserSearch.EmailAttr)
	}
	if l.config.UserSearch.CnAttr != "" {
		req.Attributes = append(req.Attributes, l.config.UserSearch.CnAttr)
	}
	if l.config.GroupSearch.LinkUserAttr != "" {
		req.Attributes = append(req.Attributes, l.config.GroupSearch.LinkUserAttr)
	}

	searchDesc := fmt.Sprintf("baseDN:'%s' scope:'%s' filter:'%s'", req.BaseDN, scopeString(req.Scope), req.Filter)
	resp, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("search [%s] failed: %v", searchDesc, err)
	}
	logger.Debug(fmt.Sprintf("Performing search [%s] -> Found %d entries", searchDesc, len(resp.Entries)))

	switch n := len(resp.Entries); n {
	case 0:
		logger.Debug("No results returned for filter", "filter", filter)
		return nil, nil
	case 1:
		logger.Debug(fmt.Sprintf("username %q mapped to entry %s", login, resp.Entries[0].DN), "login", login, "entry", resp.Entries[0].DN)
		return resp.Entries[0], nil
	default:
		return nil, fmt.Errorf("filter returned multiple (%d) results: %q", n, filter)
	}
}

// serviceBind performs the service-account (search) bind. When bindPW is empty
// we use UnauthenticatedBind because go-ldap/v3 rejects simple Bind with an
// empty password (CVE-2017-14623 hardening). An empty bindDN+bindPW therefore
// maps to an intentional anonymous bind.
func serviceBind(conn *ldap.Conn, bindDN, bindPW string) error {
	if bindPW == "" {
		return conn.UnauthenticatedBind(bindDN)
	}
	return conn.Bind(bindDN, bindPW)
}

func scopeString(i int) string {
	switch i {
	case ldap.ScopeBaseObject:
		return "base"
	case ldap.ScopeSingleLevel:
		return "one"
	case ldap.ScopeWholeSubtree:
		return "sub"
	default:
		return ""
	}
}

func (l *ldapAuthenticator) checkPassword(ctx context.Context, conn *ldap.Conn, user ldap.Entry, password string) (proto.Status, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	if password == "" {
		return proto.PasswordFail, nil
	}
	// Try to authenticate as the distinguished name.
	bindDesc := fmt.Sprintf("conn.Bind(%s, %s)", user.DN, "xxxxxxxx")
	if err := conn.Bind(user.DN, password); err != nil {
		// Detect a bad password through the LDAP error code.
		if ldapErr, ok := err.(*ldap.Error); ok {
			switch ldapErr.ResultCode {
			case ldap.LDAPResultInvalidCredentials:
				logger.Debug(fmt.Sprintf("%s => invalid password", bindDesc), "bindDesc", bindDesc)
				return proto.PasswordFail, nil
			case ldap.LDAPResultConstraintViolation:
				// Should be a Warning
				logger.Error(fmt.Sprintf("%s => constraint violation: %s", bindDesc, ldapErr.Error()), "bindDesc", bindDesc)
				return proto.PasswordFail, nil
			}
		} // will also catch all ldap.Error without a case statement above
		return proto.PasswordFail, fmt.Errorf("%s => failed: %v", bindDesc, err)
	}
	logger.Debug(fmt.Sprintf("%s => success", bindDesc), "bindDesc", bindDesc)
	return proto.PasswordChecked, nil
}

func (l *ldapAuthenticator) lookupGroups(ctx context.Context, conn *ldap.Conn, user ldap.Entry) ([]string, error) {
	logger := logr.FromContextAsSlogLogger(ctx)
	ldapGroups := make([]*ldap.Entry, 0, 2)
	groups := make([]string, 0, 2)
	for _, attr := range getAttrs(user, l.config.GroupSearch.LinkUserAttr) {
		var req *ldap.SearchRequest
		filter := "(objectClass=top)" // The only way I found to have a pass through filter
		if l.config.GroupSearch.Filter != "" {
			filter = l.config.GroupSearch.Filter
		}
		if strings.ToUpper(l.config.GroupSearch.LinkGroupAttr) == "DN" {
			req = &ldap.SearchRequest{
				BaseDN:     attr,
				Filter:     filter,
				Scope:      ldap.ScopeBaseObject,
				Attributes: []string{l.config.GroupSearch.NameAttr},
			}
		} else {
			filter := fmt.Sprintf("(%s=%s)", l.config.GroupSearch.LinkGroupAttr, ldap.EscapeFilter(attr))
			if l.config.GroupSearch.Filter != "" {
				filter = fmt.Sprintf("(&%s%s)", l.config.GroupSearch.Filter, filter)
			}
			req = &ldap.SearchRequest{
				BaseDN:     l.config.GroupSearch.BaseDN,
				Filter:     filter,
				Scope:      l.groupSearchScope,
				Attributes: []string{l.config.GroupSearch.NameAttr},
			}

		}
		searchDesc := fmt.Sprintf("baseDN:'%s' scope:'%s' filter:'%s'", req.BaseDN, scopeString(req.Scope), req.Filter)
		resp, err := conn.Search(req)
		if err != nil {
			return []string{}, fmt.Errorf("search [%s] failed: %v", searchDesc, err)
		}
		logger.Debug(fmt.Sprintf("Performing search [%s] -> Found %d entries", searchDesc, len(resp.Entries)), "searchDesc", searchDesc)
		ldapGroups = append(ldapGroups, resp.Entries...)
	}
	for _, ldapGroup := range ldapGroups {
		gname := ldapGroup.GetAttributeValue(l.config.GroupSearch.NameAttr)
		if gname != "" {
			groups = append(groups, gname)
		}
	}
	return groups, nil
}

func getAttrs(e ldap.Entry, name string) []string {
	if name == "DN" {
		return []string{e.DN}
	}
	for _, a := range e.Attributes {
		if a.Name == name {
			return a.Values
		}
	}
	return []string{}
}

func getAttr(e ldap.Entry, name string) string {
	if name == "" {
		return ""
	}
	if a := getAttrs(e, name); len(a) > 0 {
		return a[0]
	}
	return ""
}
