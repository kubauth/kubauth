package sessionstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// KubeSsoStore implements scs.Store backed by the SsoSession CRD.
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
	ctx := context.Background()
	var sess kubauthv1alpha1.SsoSession
	name := encodeName(token)
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: s.namespace, Name: name}, &sess); err != nil {
		return nil, false, client.IgnoreNotFound(err)
	}
	if sess.Annotations == nil {
		return nil, false, nil
	}
	raw, ok := sess.Annotations[annotationRawSession]
	if !ok || raw == "" {
		return nil, false, nil
	}
	return []byte(raw), true, nil
}

// Commit stores or updates the SsoSession resource, mirroring important fields.
func (s *KubeSsoStore) Commit(token string, b []byte, expiry time.Time) error {
	ctx := context.Background()
	// Decode the envelope to extract mirrored fields
	var env sessionEnvelope
	if len(b) > 0 {
		if err := json.Unmarshal(b, &env); err != nil {
			return err
		}
	}

	login, claims, fullName := extractUser(env.Values)

	// Upsert SsoSession
	var existing kubauthv1alpha1.SsoSession
	name := encodeName(token)
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
	ctx := context.Background()
	name := encodeName(token)
	return s.client.Delete(ctx, &kubauthv1alpha1.SsoSession{ObjectMeta: metav1.ObjectMeta{Namespace: s.namespace, Name: name}})
}

// All returns all session tokens using spec.webToken.
func (s *KubeSsoStore) All() ([]string, error) {
	ctx := context.Background()
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
