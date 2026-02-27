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
	"time"

	"github.com/mohae/deepcopy"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// Ensure OIDCSession implements both openid.Session and oauth2.JWTSessionContainer
var _ openid.Session = (*OIDCSession)(nil)
var _ oauth2.JWTSessionContainer = (*OIDCSession)(nil)

// OIDCSession is a session type that supports both OpenID Connect ID tokens
// and JWT access tokens. It implements openid.Session for ID tokens and
// oauth2.JWTSessionContainer for JWT access tokens.
type OIDCSession struct {
	IDTokenClaims_ *jwt.IDTokenClaims             `json:"id_token_claims"`
	JWTClaims_     *jwt.JWTClaims                 `json:"jwt_claims"`
	Headers        *jwt.Headers                   `json:"headers"`
	ExpiresAt      map[fosite.TokenType]time.Time `json:"expires_at"`
	Username       string                         `json:"username"`
	Subject        string                         `json:"subject"`
}

// NewOIDCSession creates a new OIDCSession with initialized claims and headers
//func NewOIDCSession() *OIDCSession {
//	now := time.Now().UTC()
//	return &OIDCSession{
//		IDTokenClaims_: &jwt.IDTokenClaims{
//			RequestedAt: now,
//		},
//		JWTClaims_: &jwt.JWTClaims{
//			IssuedAt: now,
//		},
//		Headers:   &jwt.Headers{},
//		ExpiresAt: make(map[fosite.TokenType]time.Time),
//	}
//}

// Clone creates a deep copy of the session
func (s *OIDCSession) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	return deepcopy.Copy(s).(fosite.Session)
}

func (s *OIDCSession) SetAudience(audience []string) {
	s.IDTokenClaims_.Audience = audience
	s.JWTClaims_.Audience = audience
}

// SetExpiresAt sets the expiration time for a token type
func (s *OIDCSession) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}
	s.ExpiresAt[key] = exp
}

// GetExpiresAt gets the expiration time for a token type
func (s *OIDCSession) GetExpiresAt(key fosite.TokenType) time.Time {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}
	if _, ok := s.ExpiresAt[key]; !ok {
		return time.Time{}
	}
	return s.ExpiresAt[key]
}

// GetUsername returns the username
func (s *OIDCSession) GetUsername() string {
	if s == nil {
		return ""
	}
	return s.Username
}

// SetSubject sets the subject
func (s *OIDCSession) SetSubject(subject string) {
	s.Subject = subject
}

// GetSubject returns the subject
func (s *OIDCSession) GetSubject() string {
	if s == nil {
		return ""
	}
	return s.Subject
}

// --- OpenID Connect Session interface (for ID tokens) ---

// IDTokenHeaders returns headers for ID token generation
func (s *OIDCSession) IDTokenHeaders() *jwt.Headers {
	if s.Headers == nil {
		s.Headers = &jwt.Headers{}
	}
	return s.Headers
}

// IDTokenClaims returns claims for ID token generation
func (s *OIDCSession) IDTokenClaims() *jwt.IDTokenClaims {
	if s.IDTokenClaims_ == nil {
		s.IDTokenClaims_ = &jwt.IDTokenClaims{}
	}
	return s.IDTokenClaims_
}

// --- JWT Session Container interface (for JWT access tokens) ---

// GetJWTClaims returns claims for JWT access token generation
func (s *OIDCSession) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.JWTClaims_ == nil {
		s.JWTClaims_ = &jwt.JWTClaims{}
	}
	return s.JWTClaims_
}

// GetJWTHeader returns headers for JWT access token generation
func (s *OIDCSession) GetJWTHeader() *jwt.Headers {
	if s.Headers == nil {
		s.Headers = &jwt.Headers{}
	}
	return s.Headers
}
