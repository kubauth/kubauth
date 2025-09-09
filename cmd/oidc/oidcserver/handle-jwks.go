package oidcserver

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
)

// Handle JWKS endpoint
func (s *OIDCServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	// Return the public key in JWKS format
	publicKey := s.privateKey.Public().(*rsa.PublicKey)

	// Convert RSA public key components to base64url encoding
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	// Ensure proper byte length for base64url encoding
	if len(nBytes)%2 == 1 {
		nBytes = append([]byte{0}, nBytes...)
	}
	if len(eBytes)%2 == 1 {
		eBytes = append([]byte{0}, eBytes...)
	}

	// Create JWK from RSA public key
	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": s.keyID,
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}

	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
