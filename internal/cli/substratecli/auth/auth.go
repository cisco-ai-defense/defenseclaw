// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package auth signs the substrate launcher in: cluster contexts
// (non-secret, a JSON file under the DefenseClaw state directory), the
// OIDC device authorization grant for people, workload tokens for CI, the
// Kubernetes identity of the current kubeconfig for installs without an
// OIDC provider, an OS keychain token store and a token source that
// refreshes on demand.
//
// Token values never appear in errors, in Describe() or in the String
// form of a Token.
package auth

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Environment variables read by this package.
const (
	EnvContext            = "DEFENSECLAW_SUBSTRATE_CONTEXT"
	EnvAdminURL           = "DEFENSECLAW_SUBSTRATE_ADMIN_URL"
	EnvIssuer             = "DEFENSECLAW_SUBSTRATE_ISSUER"
	EnvClientID           = "DEFENSECLAW_SUBSTRATE_CLIENT_ID"
	EnvWorkloadAudience   = "DEFENSECLAW_SUBSTRATE_WORKLOAD_AUDIENCE"
	EnvTokenStore         = "DEFENSECLAW_SUBSTRATE_TOKEN_STORE"
	EnvWorkloadTokenFile  = "DEFENSECLAW_SUBSTRATE_WORKLOAD_TOKEN_FILE"
	EnvK8sTokenFile       = "DEFENSECLAW_SUBSTRATE_K8S_TOKEN_FILE"
	EnvGitHubRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	EnvGitHubRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
	// EnvKube=1 (or true) turns the context into a Kubernetes-identity
	// context for one run (CI); 0 or false turns it off.
	EnvKube = "DEFENSECLAW_SUBSTRATE_KUBE"
	// EnvKubeconfig is the standard kubeconfig list variable.
	EnvKubeconfig = "KUBECONFIG"
)

const (
	// KindPerson marks a token from the device flow.
	KindPerson = "person"
	// KindWorkload marks a CI workload token.
	KindWorkload = "workload"
	// KindKube marks a bearer read from the kubeconfig: the gateway
	// verifies it with a TokenReview and the person is the Kubernetes
	// user (id kind k8s_user).
	KindKube = "k8s_user"

	// DefaultWorkloadAudience is the audience a workload token must carry
	// when the context sets no workload_audience. It must be the audience
	// the cluster trusts for the CI identity provider (workload_oidc).
	DefaultWorkloadAudience = "defenseclaw"

	keychainService = "defenseclaw-substrate"
	loginHint       = "run: defenseclaw substrate login"
)

// DefaultScopes returns the scopes asked for when a context names none.
func DefaultScopes() []string { return []string{"openid", "profile", "email", "groups"} }

// ErrNotSignedIn says there is no usable sign-in. Callers map it to exit
// code 4 with errors.Is.
var ErrNotSignedIn = errors.New("you are not signed in; " + loginHint)

// notSignedIn is ErrNotSignedIn with a reason.
type notSignedIn struct{ reason string }

func (e *notSignedIn) Error() string {
	return "you are not signed in (" + e.reason + "); " + loginHint
}

func (e *notSignedIn) Is(target error) bool { return target == ErrNotSignedIn }

func errNotSignedIn(reason string) error { return &notSignedIn{reason: reason} }

// StateDir is the DefenseClaw state directory (DEFENSECLAW_HOME, else
// ~/.defenseclaw), the same one the rest of DefenseClaw uses. Substrate
// files live in <StateDir>/substrate/.
func StateDir() string { return config.DefaultDataPath() }

func substrateDir() string { return filepath.Join(StateDir(), "substrate") }

// ContextsPath is the context file.
func ContextsPath() string { return filepath.Join(substrateDir(), "contexts.json") }

func tokenDir() string { return filepath.Join(substrateDir(), "tokens") }

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ValidName checks a context name: 1-63 letters, digits, '.', '_' or
// '-', starting with a letter or digit. Names are used as keychain
// accounts and file names, so nothing else is allowed.
func ValidName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("context name %q is not valid: use 1-63 letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	return nil
}
