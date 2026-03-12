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
	"net/http/httptest"
	"testing"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

func TestImpersonationBypassAuthenticator(t *testing.T) {
	tests := []struct {
		name                string
		enabled             bool
		authorization       string
		impersonateUser     string
		impersonateGroups   []string
		impersonateUID      string
		impersonateExtra    map[string][]string
		verifySANamespace   string
		verifySAName        string
		delegateResponse    *authenticator.Response
		delegateOK          bool
		delegateErr         error
		expectDelegateCalls int
		expectBypass        bool
		expectErr           string
	}{
		{
			name:              "bypasses delegate when enabled and impersonation user header is present",
			enabled:           true,
			authorization:     "Bearer sa-token",
			impersonateUser:   "jane.doe@example.com",
			impersonateGroups: []string{"developers", "admins"},
			impersonateUID:    "06f6ce97-e2c5-4ab8-7ba5-7654dd08d52b",
			impersonateExtra: map[string][]string{
				"scopes":             {"view", "development"},
				"acme.com%2Fproject": {"some-project"},
			},
			expectDelegateCalls: 0,
			expectBypass:        true,
		},
		{
			name:              "bypasses after tokenreview verifies configured service account",
			enabled:           true,
			authorization:     "Bearer sa-token",
			impersonateUser:   "jane.doe@example.com",
			verifySANamespace: "observability",
			verifySAName:      "proxy-client",
			delegateResponse: &authenticator.Response{User: &user.DefaultInfo{
				Name: "system:serviceaccount:observability:proxy-client",
			}},
			delegateOK:          true,
			expectDelegateCalls: 1,
			expectBypass:        true,
		},
		{
			name:              "fails bypass when tokenreview user is different service account",
			enabled:           true,
			authorization:     "Bearer sa-token",
			impersonateUser:   "jane.doe@example.com",
			verifySANamespace: "observability",
			verifySAName:      "proxy-client",
			delegateResponse: &authenticator.Response{User: &user.DefaultInfo{
				Name: "system:serviceaccount:default:other",
			}},
			delegateOK:          true,
			expectDelegateCalls: 1,
			expectBypass:        false,
			expectErr:           "token is not for the configured service account",
		},
		{
			name:                "fails bypass when tokenreview does not authenticate token",
			enabled:             true,
			authorization:       "Bearer sa-token",
			impersonateUser:     "jane.doe@example.com",
			verifySANamespace:   "observability",
			verifySAName:        "proxy-client",
			delegateResponse:    nil,
			delegateOK:          false,
			expectDelegateCalls: 1,
			expectBypass:        false,
			expectErr:           "token review did not authenticate the bearer token",
		},
		{
			name:                "falls back when impersonation user header is missing",
			enabled:             true,
			authorization:       "Bearer sa-token",
			delegateResponse:    &authenticator.Response{User: &user.DefaultInfo{Name: "delegate-user"}},
			delegateOK:          true,
			expectDelegateCalls: 1,
			expectBypass:        false,
		},
		{
			name:                "falls back when mode is disabled",
			enabled:             false,
			authorization:       "Bearer sa-token",
			impersonateUser:     "jane.doe@example.com",
			delegateResponse:    &authenticator.Response{User: &user.DefaultInfo{Name: "delegate-user"}},
			delegateOK:          true,
			expectDelegateCalls: 1,
			expectBypass:        false,
		},
		{
			name:                "falls back when authorization is not bearer",
			enabled:             true,
			authorization:       "Basic abc123",
			impersonateUser:     "jane.doe@example.com",
			delegateErr:         errors.New("delegate-error"),
			expectDelegateCalls: 1,
			expectBypass:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delegate := &fakeAuthenticator{
				response: tt.delegateResponse,
				ok:       tt.delegateOK,
				err:      tt.delegateErr,
			}
			authenticator := NewImpersonationBypassAuthenticator(delegate, &ImpersonationConfig{
				Enabled:           tt.enabled,
				UserHeader:        "Impersonate-User",
				GroupHeader:       "Impersonate-Group",
				UIDHeader:         "Impersonate-Uid",
				ExtraHeaderPrefix: "Impersonate-Extra-",
				ServiceAccount: &ImpersonationServiceAccountConfig{
					Namespace: tt.verifySANamespace,
					Name:      tt.verifySAName,
				},
			})

			req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			req.Header.Set("Authorization", tt.authorization)
			if tt.impersonateUser != "" {
				req.Header.Set("Impersonate-User", tt.impersonateUser)
			}
			for _, group := range tt.impersonateGroups {
				req.Header.Add("Impersonate-Group", group)
			}
			if tt.impersonateUID != "" {
				req.Header.Set("Impersonate-Uid", tt.impersonateUID)
			}
			for key, values := range tt.impersonateExtra {
				headerName := "Impersonate-Extra-" + key
				for _, value := range values {
					req.Header.Add(headerName, value)
				}
			}

			res, ok, err := authenticator.AuthenticateRequest(req)

			if delegate.calls != tt.expectDelegateCalls {
				t.Fatalf("expected delegate calls %d, got %d", tt.expectDelegateCalls, delegate.calls)
			}

			if !tt.expectBypass {
				if tt.expectErr != "" {
					if err == nil || err.Error() != tt.expectErr {
						t.Fatalf("expected error %q, got %v", tt.expectErr, err)
					}
					if ok {
						t.Fatalf("expected unauthenticated result when error is returned")
					}
					return
				}

				if ok != tt.delegateOK {
					t.Fatalf("expected delegate ok=%v, got %v", tt.delegateOK, ok)
				}
				if !errors.Is(err, tt.delegateErr) {
					t.Fatalf("expected delegate err=%v, got %v", tt.delegateErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !ok {
				t.Fatalf("expected authenticated response")
			}
			if got := res.User.GetName(); got != tt.impersonateUser {
				t.Fatalf("expected user name %q, got %q", tt.impersonateUser, got)
			}
			if got := res.User.GetUID(); got != tt.impersonateUID {
				t.Fatalf("expected uid %q, got %q", tt.impersonateUID, got)
			}
			if len(res.User.GetGroups()) != len(tt.impersonateGroups) {
				t.Fatalf("expected %d groups, got %d", len(tt.impersonateGroups), len(res.User.GetGroups()))
			}
			if len(tt.impersonateExtra) > 0 {
				if got := res.User.GetExtra()["scopes"]; len(got) != 2 || got[0] != "view" || got[1] != "development" {
					t.Fatalf("expected scopes extra to be preserved, got %v", got)
				}
				if got := res.User.GetExtra()["acme.com/project"]; len(got) != 1 || got[0] != "some-project" {
					t.Fatalf("expected decoded extra key acme.com/project, got %v", got)
				}
			}
		})
	}
}

type fakeAuthenticator struct {
	calls    int
	response *authenticator.Response
	ok       bool
	err      error
}

func (a *fakeAuthenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	a.calls++
	return a.response, a.ok, a.err
}
