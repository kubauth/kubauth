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

package sessionstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/go-logr/logr"
	"time"

	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// KubeSsoStore implements scs CtxStore and IterableCtxStore backed by the SsoSession CRD.
// It assumes that the session values contain a user object compatible with userdb.User
// and mirrors key fields into the CRD spec: login, fullName, webToken, claims, deadline, expiry.
type KubeSsoStore struct {
	client    client.Client
	namespace string
}

func NewKubeSsoStore(k8sClient client.Client, namespace string) *KubeSsoStore {
	return &KubeSsoStore{client: k8sClient, namespace: namespace}
}

const annotationRawSession = "kubauth.kubotal.io/session"

type sessionEnvelope struct {
	Deadline time.Time              `json:"deadline"`
	Values   map[string]interface{} `json:"values"`
}

// Find returns the raw session bytes if present.
func (s *KubeSsoStore) Find(token string) ([]byte, bool, error) {
	return s.FindCtx(context.Background(), token)
}

// FindCtx returns the raw session bytes if present using provided context.
func (s *KubeSsoStore) FindCtx(ctx context.Context, token string) ([]byte, bool, error) {
	var sess kubauthv1alpha1.SsoSession
	name := encodeName(token)
	logger := logr.FromContextAsSlogLogger(ctx)
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: s.namespace, Name: name}, &sess); err != nil {
		logger.Debug("SsoSession not found", "token", token, "encoded", name)
		return nil, false, client.IgnoreNotFound(err)
	}
	if sess.Annotations == nil {
		logger.Debug("No annotation on SsoSession", "token", token, "encoded", name)
		return nil, false, nil
	}
	raw, ok := sess.Annotations[annotationRawSession]
	if !ok || raw == "" {
		logger.Debug("Missing annotation on SsoSession", "token", token, "encoded", name)
		return nil, false, nil
	}
	logger.Debug("Found SsoSession", "token", token, "encoded", name)
	return []byte(raw), true, nil
}

// Commit stores or updates the SsoSession resource, mirroring important fields.
func (s *KubeSsoStore) Commit(token string, b []byte, expiry time.Time) error {
	return s.CommitCtx(context.Background(), token, b, expiry)
}

// CommitCtx stores or updates the SsoSession resource using provided context.
func (s *KubeSsoStore) CommitCtx(ctx context.Context, token string, b []byte, expiry time.Time) error {
	// Decode the envelope to extract mirrored fields
	logger := logr.FromContextAsSlogLogger(ctx)
	var env sessionEnvelope
	if len(b) > 0 {
		if err := json.Unmarshal(b, &env); err != nil {
			return err
		}
	}
	login, claims, fullName := extractUser(env.Values)
	if login == "" {
		// We don't store empty session
		logger.Debug("No login on SsoSession", "token", token, "encoded", env.Values)
		return nil
	}
	// Upsert SsoSession
	var existing kubauthv1alpha1.SsoSession
	name := encodeName(token)
	logger.Debug("Commiting session", "login", login, "claims", claims, "fullName", fullName, "token", token, "expiry", expiry, "encoded", name)
	key := types.NamespacedName{Namespace: s.namespace, Name: name}
	err := s.client.Get(ctx, key, &existing)
	if err != nil {
		// Create new
		ss := kubauthv1alpha1.SsoSession{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   s.namespace,
				Name:        name,
				Annotations: map[string]string{annotationRawSession: string(b)},
			},
			Spec: kubauthv1alpha1.SsoSessionSpec{
				Login:    login,
				FullName: fullName,
				WebToken: token,
				Deadline: metav1.NewTime(env.Deadline),
				Expiry:   metav1.NewTime(expiry),
			},
		}
		if claims != nil {
			raw, _ := json.Marshal(claims)
			ss.Spec.Claims = &apiextensionsv1.JSON{Raw: raw}
		}
		return s.client.Create(ctx, &ss)
	}

	// Update existing
	if existing.Annotations == nil {
		existing.Annotations = map[string]string{}
	}
	existing.Annotations[annotationRawSession] = string(b)
	existing.Spec.Login = login
	existing.Spec.FullName = fullName
	existing.Spec.WebToken = token
	existing.Spec.Deadline = metav1.NewTime(env.Deadline)
	existing.Spec.Expiry = metav1.NewTime(expiry)
	if claims != nil {
		raw, _ := json.Marshal(claims)
		existing.Spec.Claims = &apiextensionsv1.JSON{Raw: raw}
	} else {
		existing.Spec.Claims = nil
	}
	return s.client.Update(ctx, &existing)
}

// Delete removes the SsoSession resource.
func (s *KubeSsoStore) Delete(token string) error {
	return s.DeleteCtx(context.Background(), token)
}

// DeleteCtx removes the SsoSession resource using provided context.
func (s *KubeSsoStore) DeleteCtx(ctx context.Context, token string) error {
	name := encodeName(token)
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Deleting session", "token", token, "encoded", name)
	return s.client.Delete(ctx, &kubauthv1alpha1.SsoSession{ObjectMeta: metav1.ObjectMeta{Namespace: s.namespace, Name: name}})
}

// All returns all session tokens using spec.webToken.
func (s *KubeSsoStore) All() ([]string, error) {
	return s.AllCtx(context.Background())
}

// AllCtx returns all session tokens using spec.webToken with provided context.
func (s *KubeSsoStore) AllCtx(ctx context.Context) ([]string, error) {
	var list kubauthv1alpha1.SsoSessionList
	if err := s.client.List(ctx, &list, client.InNamespace(s.namespace)); err != nil {
		return nil, err
	}
	res := make([]string, 0, len(list.Items))
	for i := range list.Items {
		if t := list.Items[i].Spec.WebToken; t != "" {
			res = append(res, t)
		}
	}
	logger := logr.FromContextAsSlogLogger(ctx)
	logger.Debug("Listing sessions", "count", len(res))

	return res, nil
}

// extractUser tries to find a value shaped like userdb.User (fields Login, Claims, FullName)
// within the values map. It prioritizes key "ssoUser" if present.
func extractUser(values map[string]interface{}) (login string, claims map[string]interface{}, fullName string) {
	if values == nil {
		return "", nil, ""
	}
	// Prefer ssoUser
	if v, ok := values["ssoUser"]; ok {
		if l, c, f, ok := asUser(v); ok {
			return l, c, f
		}
	}
	// Fallback: first value that matches
	for _, v := range values {
		if l, c, f, ok := asUser(v); ok {
			return l, c, f
		}
	}
	return "", nil, ""
}

func asUser(v interface{}) (string, map[string]interface{}, string, bool) {
	m, ok := v.(map[string]interface{})
	if !ok {
		return "", nil, "", false
	}
	loginV, ok := m["Login"]
	if !ok {
		// maybe lower-case from other codecs
		loginV, ok = m["login"]
		if !ok {
			return "", nil, "", false
		}
	}
	login, _ := loginV.(string)
	var claims map[string]interface{}
	if c, ok := m["Claims"]; ok {
		claims, _ = c.(map[string]interface{})
	} else if c, ok := m["claims"]; ok {
		claims, _ = c.(map[string]interface{})
	}
	var fullName string
	if f, ok := m["FullName"]; ok {
		fullName, _ = f.(string)
	} else if f, ok := m["fullName"]; ok {
		fullName, _ = f.(string)
	}
	return login, claims, fullName, true
}

// encodeName returns an RFC1123-compliant name derived from the token.
// It always uses a short, uniform transformation: sha256 hex with an 'h-' prefix.
func encodeName(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "h-" + hex.EncodeToString(sum[:])
}
