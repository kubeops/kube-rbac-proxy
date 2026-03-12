/*
Copyright 2026 the kube-rbac-proxy maintainers. All rights reserved.

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

package authn

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type impersonationBypassAuthenticator struct {
	delegate authenticator.Request
	cfg      *ImpersonationConfig
}

var _ authenticator.Request = (*impersonationBypassAuthenticator)(nil)

// NewImpersonationBypassAuthenticator returns a request authenticator that
// optionally bypasses delegated authentication when Kubernetes impersonation
// headers are present.
func NewImpersonationBypassAuthenticator(delegate authenticator.Request, cfg *ImpersonationConfig) authenticator.Request {
	return &impersonationBypassAuthenticator{delegate: delegate, cfg: cfg}
}

func (a *impersonationBypassAuthenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	if a == nil || a.delegate == nil {
		return nil, false, errors.New("delegate authenticator is required")
	}

	if !a.shouldBypass(req) {
		return a.delegate.AuthenticateRequest(req)
	}

	if err := a.verifyServiceAccountToken(req); err != nil {
		return nil, false, err
	}

	identity := &user.DefaultInfo{
		Name:   strings.TrimSpace(req.Header.Get(a.cfg.UserHeader)),
		UID:    strings.TrimSpace(req.Header.Get(a.cfg.UIDHeader)),
		Groups: req.Header.Values(a.cfg.GroupHeader),
		Extra:  parseImpersonationExtras(req.Header, a.cfg.ExtraHeaderPrefix),
	}

	if len(identity.Extra) == 0 {
		identity.Extra = nil
	}

	return &authenticator.Response{User: identity}, true, nil
}

func (a *impersonationBypassAuthenticator) verifyServiceAccountToken(req *http.Request) error {
	if a == nil || a.cfg == nil || req == nil {
		return nil
	}

	if !a.shouldVerifyServiceAccount() {
		return nil
	}

	response, ok, err := a.delegate.AuthenticateRequest(req)
	if err != nil {
		return err
	}
	if !ok || response == nil || response.User == nil {
		return errors.New("token review did not authenticate the bearer token")
	}

	expected := expectedServiceAccountUsername(strings.TrimSpace(a.cfg.ServiceAccount.Namespace), strings.TrimSpace(a.cfg.ServiceAccount.Name))
	if response.User.GetName() != expected {
		return errors.New("token is not for the configured service account")
	}

	return nil
}

func (a *impersonationBypassAuthenticator) shouldVerifyServiceAccount() bool {
	if a == nil || a.cfg == nil || a.cfg.ServiceAccount == nil {
		return false
	}

	ns := strings.TrimSpace(a.cfg.ServiceAccount.Namespace)
	name := strings.TrimSpace(a.cfg.ServiceAccount.Name)
	return ns != "" && name != ""
}

func expectedServiceAccountUsername(namespace, name string) string {
	return "system:serviceaccount:" + namespace + ":" + name
}

func (a *impersonationBypassAuthenticator) shouldBypass(req *http.Request) bool {
	if a == nil || a.cfg == nil || !a.cfg.Enabled {
		return false
	}

	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return false
	}

	return strings.TrimSpace(req.Header.Get(a.cfg.UserHeader)) != ""
}

func parseImpersonationExtras(header http.Header, prefix string) map[string][]string {
	if prefix == "" {
		return nil
	}

	lowerPrefix := strings.ToLower(prefix)
	extra := make(map[string][]string)
	for name, values := range header {
		lowerName := strings.ToLower(name)
		if !strings.HasPrefix(lowerName, lowerPrefix) {
			continue
		}

		rawKey := name[len(prefix):]
		decodedKey, err := url.QueryUnescape(rawKey)
		if err != nil {
			decodedKey = rawKey
		}
		key := strings.ToLower(decodedKey)
		if key == "" {
			continue
		}

		extra[key] = append(extra[key], values...)
	}

	return extra
}
