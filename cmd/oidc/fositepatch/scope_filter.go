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

package fositepatch

import (
	"context"
	"time"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/openid"
)

// claimsByScope maps each standard OIDC scope to the set of Extra
// claims it grants in the id_token (and the userinfo response).
//
// Reference: OpenID Connect Core 1.0 §5.4 "Requesting Claims using
// Scope Values".
//   https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
//
// `openid` itself grants nothing in Extra — `sub` is a top-level
// claim of IDTokenClaims, not an Extra entry.
var claimsByScope = map[string][]string{
	"profile": {
		"name", "family_name", "given_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website",
		"gender", "birthdate", "zoneinfo", "locale", "updated_at",
	},
	"email":   {"email", "email_verified", "emails"},
	"address": {"address"},
	"phone":   {"phone_number", "phone_number_verified"},
	// kubauth ships a `groups` scope: when granted, group membership
	// shows up under the `groups` claim. Not in OIDC core, but
	// follows the same scope→claim convention.
	"groups": {"groups"},
}

// alwaysAllowedClaims are Extra entries that ride every id_token
// regardless of scope. Two kinds:
//
//   - protocol-level (fosite/hydra populates them as part of the
//     spec-defined token shape, not as user claims),
//   - kubauth extensions that the existing e2e suite (and several
//     downstream clients) rely on. These are emitted as a
//     deliberate kubauth extension; the OpenID Conformance Suite
//     flags them as non-requested but lets the test FINISHED with
//     WARNING — acceptable.
//
// Notably absent: `rat` (hydra/fosite's "requested at"). Strict
// OIDC RPs flag it; drop from id_token. Still observable via
// `/oauth2/introspect` for clients that genuinely care.
var alwaysAllowedClaims = map[string]struct{}{
	// Protocol-level
	"azp":       {}, // authorized party — kubauth adds it explicitly
	"nonce":     {}, // echoed back from the auth request
	"at_hash":   {},
	"c_hash":    {},
	"acr":       {},
	"amr":       {},
	"auth_time": {},
	"sid":       {},
	// Kubauth extensions
	"authority": {}, // which IdP authority authenticated the user (ucrd/ldap/...)
	"uid":       {}, // POSIX numeric uid (used by downstream tooling that maps OIDC sub → host user)
}

// AllowedIDTokenClaimsFor returns the union of Extra-claim names
// that may appear in an id_token (or userinfo response) granted the
// given scopes. Unknown scopes are ignored.
//
// Exposed so handle-user-info.go can mirror the id_token filter on
// its own response.
func AllowedIDTokenClaimsFor(grantedScopes []string) map[string]struct{} {
	allowed := make(map[string]struct{}, 16)
	for k := range alwaysAllowedClaims {
		allowed[k] = struct{}{}
	}
	for _, sc := range grantedScopes {
		for _, claim := range claimsByScope[sc] {
			allowed[claim] = struct{}{}
		}
	}
	return allowed
}

// FilterExtraClaimsByScope drops any Extra entry that's not in the
// allowed set built from the granted scopes. Mutates and returns
// the same map (or a fresh one if `extra` was nil).
func FilterExtraClaimsByScope(extra map[string]interface{}, grantedScopes []string) map[string]interface{} {
	if extra == nil {
		return nil
	}
	allowed := AllowedIDTokenClaimsFor(grantedScopes)
	for k := range extra {
		if _, ok := allowed[k]; !ok {
			delete(extra, k)
		}
	}
	return extra
}

// scopeFilteringIDTokenStrategy wraps an OpenIDConnectTokenStrategy
// and prunes the session's IDTokenClaims_.Extra to the claims the
// granted scopes authorise. Without this, kubauth's id_token leaks
// every user claim regardless of scope (OIDF conformance suite
// trips on EnsureIdTokenDoesNotContainNonRequestedClaims for the
// whole oidcc-basic plan).
type scopeFilteringIDTokenStrategy struct {
	inner openid.OpenIDConnectTokenStrategy
}

// NewScopeFilteringIDTokenStrategy decorates `inner` with the
// scope-based Extra-claim filter described above.
func NewScopeFilteringIDTokenStrategy(inner openid.OpenIDConnectTokenStrategy) openid.OpenIDConnectTokenStrategy {
	return scopeFilteringIDTokenStrategy{inner: inner}
}

// GenerateIDToken filters the session's id_token Extra map by the
// requester's granted scopes, then delegates to the wrapped
// strategy.
//
// The session is the same object that handlers will serialise,
// so mutating Extra here is safe — and necessary, since fosite's
// default strategy hands the full Extra map straight into the JWT.
func (s scopeFilteringIDTokenStrategy) GenerateIDToken(ctx context.Context, lifespan time.Duration, requester fosite.Requester) (string, error) {
	if sess, ok := requester.GetSession().(*OIDCSession); ok && sess != nil && sess.IDTokenClaims_ != nil {
		granted := requester.GetGrantedScopes()
		sess.IDTokenClaims_.Extra = FilterExtraClaimsByScope(sess.IDTokenClaims_.Extra, granted)
	}
	return s.inner.GenerateIDToken(ctx, lifespan, requester)
}
