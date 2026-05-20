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

package oidcserver

import (
	"encoding/json"
	"fmt"
	"kubauth/cmd/oidc/authenticator"
	"kubauth/cmd/oidc/upstreams"
	"kubauth/internal/misc"
	"net/http"

	"github.com/go-logr/logr"
	"golang.org/x/oauth2"
)

const sessPendingUpstreamUser = "pendingUpstreamUser"

// handleUpstreamCallback completes the upstream OIDC authorization code flow and resumes Kubauth authorize.
func (s *OIDCServer) handleUpstreamCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logr.FromContextAsSlogLogger(ctx)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		logger.Error("upstream returned error", "error", errParam, "description", q.Get("error_description"))
		http.Error(w, "upstream login failed", http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		logger.Error("upstream callback missing code or state", "hasCode", code != "", "hasState", state != "")
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}
	wantState := s.LoginSessionManager.GetString(ctx, sessUpstreamState)
	if wantState == "" || wantState != state {
		logger.Error("upstream callback state mismatch")
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	name := s.LoginSessionManager.GetString(ctx, sessUpstreamProvider)
	rawQuery := s.LoginSessionManager.GetString(ctx, "authQuery")
	if name == "" || rawQuery == "" {
		logger.Error("upstream callback missing session context")
		http.Error(w, "session expired", http.StatusBadRequest)
		return
	}

	u := s.Storage.GetUpstream(ctx, name)
	if u == nil {
		logger.Error("upstream callback: unknown upstream", "upstream", name)
		http.Error(w, "unknown upstream", http.StatusBadRequest)
		return
	}
	settings, ok := u.OAuth2AuthCodeSettings()
	if !ok || settings == nil {
		logger.Error("upstream callback: upstream misconfigured", "upstream", name)
		http.Error(w, "upstream misconfigured", http.StatusBadRequest)
		return
	}

	cfg := oauth2.Config{
		ClientID:     settings.ClientID,
		ClientSecret: settings.ClientSecret,
		RedirectURL:  settings.RedirectURL,
		Endpoint:     settings.Endpoint,
		Scopes:       settings.Scopes,
	}
	clientCtx := u.ClientContext(ctx)

	var tok *oauth2.Token
	var err error
	if s.LoginSessionManager.GetString(ctx, sessUpstreamPKCE) == "1" {
		verifier := s.LoginSessionManager.GetString(ctx, sessUpstreamVerifier)
		tok, err = cfg.Exchange(clientCtx, code, oauth2.VerifierOption(verifier))
	} else {
		tok, err = cfg.Exchange(clientCtx, code)
	}
	if err != nil {
		logger.Error("upstream token exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	// The base claim set (idClaims) is the OIDC claims set from the upstream provider.

	ts := cfg.TokenSource(clientCtx, tok)
	var idClaims upstreams.ClaimSet
	if rawID, ok := tok.Extra("id_token").(string); ok && rawID != "" {
		idClaims, err = u.ParseAndVerifyIDToken(clientCtx, rawID)
		idClaims = misc.NormalizeStringArray(idClaims)
		if err != nil {
			logger.Error("upstream id_token verification failed", "error", err)
			http.Error(w, "invalid id_token", http.StatusBadGateway)
			return
		}
		wantNonce := s.LoginSessionManager.GetString(ctx, sessUpstreamNonce)
		gotNonce, _ := idClaims["nonce"].(string)
		if wantNonce != "" && gotNonce != wantNonce {
			logger.Error("upstream id_token nonce mismatch")
			http.Error(w, "invalid nonce", http.StatusBadRequest)
			return
		}
	}
	// If `UseUserInfo: true`, then userInfo is requested and the result is merged on top of the base claim
	if u.UseUserInfo() {
		uiClaims, err := u.FetchUserInfoClaims(clientCtx, ts)
		uiClaims = misc.NormalizeStringArray(uiClaims)
		if err != nil {
			logger.Error("upstream userinfo failed", "error", err)
			http.Error(w, "userinfo failed", http.StatusBadGateway)
			return
		}
		s.upstreamPrintf("User Info Claims:%s\n", misc.Any2Yaml(uiClaims))
		idClaims = misc.MergeMaps(idClaims, uiClaims)
	}
	s.upstreamPrintf("Upstream ID Claims:%s\n", misc.Any2Yaml(idClaims))

	// Then, the set of `claimRenamings` is applied.
	idClaims = u.PerformRenaming(idClaims)

	s.upstreamPrintf("Upstream claim after renaming:%s\n", misc.Any2Yaml(idClaims))

	idClaims = u.CleanupClaims(idClaims)

	s.upstreamPrintf("Upstream claims after cleanup:%s\n", misc.Any2Yaml(idClaims))

	sub, _ := idClaims["sub"].(string)
	if sub == "" {
		logger.Error("Missing sub claim")
		http.Error(w, "Missing sub claim", http.StatusBadGateway)
	}

	var user *authenticator.OidcUser = nil
	if u.LocalEnrichment() {
		user, _, err = s.Authenticator.Identify(ctx, sub, "")
		if err != nil {
			logger.Error("Error authenticating user", "error", err)
			http.Error(w, "Error authenticating user", http.StatusInternalServerError)
		}
		if user != nil {
			user.Claims = misc.NormalizeStringArray(user.Claims)
			x := misc.MergeMaps(idClaims, user.Claims)
			user.Claims = x
			s.upstreamPrintf("User login:'%s'  fullName:'%s' enrichment:true claims:%s\n", user.Login, user.FullName, misc.Any2Yaml(user.Claims))
		}
	}
	if user == nil {
		// No info from local IDP. Build our user from upstream claims (After renaming and cleanup)
		fullName := ""
		if s, ok := idClaims["name"].(string); ok {
			fullName = s
		}
		user = &authenticator.OidcUser{
			Login:    sub,
			Claims:   idClaims,
			FullName: fullName,
		}
		s.upstreamPrintf("User login:'%s'  fullName:'%s' enrichment:false claims:%s\n", user.Login, user.FullName, misc.Any2Yaml(user.Claims))
	}

	_ = s.SsoSessionManager.RenewToken(ctx)

	s.LoginSessionManager.Remove(ctx, sessUpstreamState)
	s.LoginSessionManager.Remove(ctx, sessUpstreamNonce)
	s.LoginSessionManager.Remove(ctx, sessUpstreamVerifier)
	s.LoginSessionManager.Remove(ctx, sessUpstreamPKCE)
	s.LoginSessionManager.Remove(ctx, sessUpstreamProvider)

	switch s.SsoMode {
	case SsoOnDemand:
		// Defer SSO decision to the user via the welcome page.
		userJSON, err := json.Marshal(user)
		if err != nil {
			logger.Error("marshal pending upstream user", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.LoginSessionManager.Put(ctx, sessPendingUpstreamUser, string(userJSON))
		http.Redirect(w, r, "/upstream/welcome", http.StatusFound)
		return
	case SsoAlways:
		s.SsoSessionManager.Put(ctx, "ssoUser", user)
	}
	s.completeUpstreamAuthorize(ctx, w, rawQuery, user)
}

func (s *OIDCServer) upstreamPrintf(format string, a ...interface{}) {
	if s.DumpUpstreamClaims {
		fmt.Printf(format, a...)
	}
}
