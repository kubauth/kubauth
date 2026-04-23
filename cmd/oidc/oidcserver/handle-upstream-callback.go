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
	"net/http"

	"github.com/go-logr/logr"
	"golang.org/x/oauth2"
)

const sessPendingUpstreamUser = "pendingUpstreamUser"

func mergeUpstreamClaimMaps(userinfo, idToken map[string]interface{}) map[string]interface{} {
	n := 0
	if userinfo != nil {
		n += len(userinfo)
	}
	if idToken != nil {
		n += len(idToken)
	}
	out := make(map[string]interface{}, n)
	for k, v := range userinfo {
		out[k] = v
	}
	for k, v := range idToken {
		out[k] = v
	}
	return out
}

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
	}
	xctx := u.ClientContext(ctx)

	var tok *oauth2.Token
	var err error
	if s.LoginSessionManager.GetString(ctx, sessUpstreamPKCE) == "1" {
		verifier := s.LoginSessionManager.GetString(ctx, sessUpstreamVerifier)
		tok, err = cfg.Exchange(xctx, code, oauth2.VerifierOption(verifier))
	} else {
		tok, err = cfg.Exchange(xctx, code)
	}
	if err != nil {
		logger.Error("upstream token exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	ts := cfg.TokenSource(xctx, tok)
	var idClaims map[string]interface{}
	if rawID, ok := tok.Extra("id_token").(string); ok && rawID != "" {
		idClaims, err = u.ParseAndVerifyIDToken(xctx, rawID)
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

	uiClaims, err := u.FetchUserInfoClaims(xctx, ts)
	if err != nil {
		logger.Error("upstream userinfo failed", "error", err)
		http.Error(w, "userinfo failed", http.StatusBadGateway)
		return
	}
	merged := mergeUpstreamClaimMaps(uiClaims, idClaims)
	if len(merged) == 0 {
		http.Error(w, "no claims from upstream", http.StatusBadGateway)
		return
	}

	user, err := mapUpstreamClaimsToUserClaims(merged)
	if err != nil {
		logger.Error("upstream claims mapping failed", "error", err)
		http.Error(w, "invalid user claims", http.StatusBadGateway)
		return
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
