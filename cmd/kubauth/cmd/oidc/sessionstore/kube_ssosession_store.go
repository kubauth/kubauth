package sessionstore

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// KubeSsoSessionStore implements scs.Store backed by the SsoSession CRD.
// It assumes that the session values contain a user object compatible with userdb.User
// and mirrors key fields into the CRD spec: login, claims, deadline, expiry.
type KubeSsoSessionStore struct {
	client    client.Client
	namespace string
}

func NewKubeSsoSessionStore(k8sClient client.Client, namespace string) *KubeSsoSessionStore {
	return &KubeSsoSessionStore{client: k8sClient, namespace: namespace}
}

const annotationRawSession = "kubauth.kubotal.io/session"

type sessionEnvelope struct {
	Deadline time.Time              `json:"deadline"`
	Values   map[string]interface{} `json:"values"`
}

// Find returns the raw session bytes if present.
func (s *KubeSsoSessionStore) Find(token string) ([]byte, bool, error) {
	ctx := context.Background()
	var sess kubauthv1alpha1.SsoSession
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: s.namespace, Name: token}, &sess); err != nil {
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
func (s *KubeSsoSessionStore) Commit(token string, b []byte, expiry time.Time) error {
	ctx := context.Background()
	// Decode the envelope to extract mirrored fields
	var env sessionEnvelope
	if len(b) > 0 {
		if err := json.Unmarshal(b, &env); err != nil {
			return err
		}
	}

	login, claims, err := extractUser(env.Values)
	if err != nil {
		return err
	}

	// Upsert SsoSession
	var existing kubauthv1alpha1.SsoSession
	key := types.NamespacedName{Namespace: s.namespace, Name: token}
	err = s.client.Get(ctx, key, &existing)
	if err != nil {
		// Create new
		ss := kubauthv1alpha1.SsoSession{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   s.namespace,
				Name:        token,
				Annotations: map[string]string{annotationRawSession: string(b)},
			},
			Spec: kubauthv1alpha1.SsoSessionSpec{
				Login:    login,
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
func (s *KubeSsoSessionStore) Delete(token string) error {
	ctx := context.Background()
	return s.client.Delete(ctx, &kubauthv1alpha1.SsoSession{ObjectMeta: metav1.ObjectMeta{Namespace: s.namespace, Name: token}})
}

// Following is commented out, as polishToken() make this wring

//// All returns all session tokens (names of SsoSession resources).
//func (s *KubeSsoSessionStore) All() ([]string, error) {
//	ctx := context.Background()
//	var list kubauthv1alpha1.SsoSessionList
//	if err := s.client.List(ctx, &list, client.InNamespace(s.namespace)); err != nil {
//		return nil, err
//	}
//	res := make([]string, 0, len(list.Items))
//	for i := range list.Items {
//		res = append(res, list.Items[i].Name)
//	}
//	return res, nil
//}

// extractUser tries to find a value shaped like userdb.User (fields Login, Claims)
// within the values map. It prioritizes key "ssoUser" if present.
func extractUser(values map[string]interface{}) (string, map[string]interface{}, error) {
	if values == nil {
		return "", nil, nil
	}
	// Prefer ssoUser
	if v, ok := values["ssoUser"]; ok {
		if login, claims, ok := asUser(v); ok {
			return login, claims, nil
		}
	}
	// Fallback: first value that matches
	for _, v := range values {
		if login, claims, ok := asUser(v); ok {
			return login, claims, nil
		}
	}
	return "", nil, errors.New("no user found in session values")
}

func asUser(v interface{}) (string, map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	if !ok {
		return "", nil, false
	}
	loginV, ok := m["Login"]
	if !ok {
		// maybe lower-case from other codecs
		loginV, ok = m["login"]
		if !ok {
			return "", nil, false
		}
	}
	login, _ := loginV.(string)
	var claims map[string]interface{}
	if c, ok := m["Claims"]; ok {
		claims, _ = c.(map[string]interface{})
	} else if c, ok := m["claims"]; ok {
		claims, _ = c.(map[string]interface{})
	}
	return login, claims, true
}
