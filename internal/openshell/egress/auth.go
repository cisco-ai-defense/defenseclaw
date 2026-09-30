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

package egress

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// Principal is the sandbox a proxy credential belongs to. BindingID is
// required and attributes every tunnel; the sandbox fields travel into events
// and unblock lookups.
type Principal struct {
	BindingID   string
	SandboxID   string
	SandboxName string
	// Mode is the sandbox's decision mode; empty uses the Decider default.
	Mode Mode
	// Decider is the sandbox's own decider, built from its resolved policy
	// (packs.Effective.EgressDecider), so one sandbox's pack, clamps and
	// unblocks never decide another's egress. Nil uses the proxy's default
	// (Options.Decider, SetDecider). Re-registering the credential with a
	// new decider applies it to later tunnels and requests, and
	// Proxy.Recheck to the open ones.
	Decider *Decider
	// LargeUploadBytes is the sandbox's own large-upload threshold (its
	// pack's egress.large_upload_mb): zero uses the counter's
	// (CounterOptions.LargeUploadBytes), negative turns the signal off for
	// the sandbox. Re-registering the credential applies a new value to
	// later tunnels and requests.
	LargeUploadBytes int64
}

// Authenticator maps a proxy credential to its principal. Implementations
// must be safe for concurrent use and should compare secrets in constant
// time.
type Authenticator interface {
	Authenticate(username, password string) (Principal, bool)
}

// SuspendingAuthenticator is an Authenticator that also knows the
// credentials it suspended (CredentialStore.Suspend). Authenticate refuses
// them; the proxy answers them with Suspended's refusal (a 403 that says
// why) instead of the 407 challenge an unknown credential gets.
type SuspendingAuthenticator interface {
	Authenticator
	Suspended(username, password string) (Principal, Decision, bool)
}

// Credential is a per-binding proxy credential. The sandbox receives it as
// the userinfo of HTTPS_PROXY/HTTP_PROXY and clients send it as
// Proxy-Authorization: Basic. It only authorizes egress the sandbox already
// has, and the proxy listens on loopback only.
type Credential struct {
	Username string
	Password string
}

const (
	credentialUserPrefix  = "dcx-"
	credentialUserBytes   = 8
	credentialSecretBytes = 32
	maxCredentialUserLen  = 64
	minCredentialPassLen  = 16
	maxCredentialPassLen  = 256
	// maxProxyAuthorizationLen bounds the base64 blob before decoding; a
	// maximal username:password pair encodes to well under this.
	maxProxyAuthorizationLen = 512
)

var (
	// ErrInvalidCredential reports a credential or principal that cannot be
	// registered.
	ErrInvalidCredential = errors.New("egress: invalid proxy credential")
	// ErrCredentialInUse reports a username already registered to a
	// different binding.
	ErrCredentialInUse = errors.New("egress: proxy username is registered to another binding")
)

// NewCredential mints a random credential: a "dcx-" username with 64 random
// bits and a 256-bit password, both hex so they embed in a proxy URL without
// escaping.
func NewCredential() (Credential, error) {
	buf := make([]byte, credentialUserBytes+credentialSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return Credential{}, fmt.Errorf("egress: mint proxy credential: %w", err)
	}
	return Credential{
		Username: credentialUserPrefix + hex.EncodeToString(buf[:credentialUserBytes]),
		Password: hex.EncodeToString(buf[credentialUserBytes:]),
	}, nil
}

// ProxyURL returns the proxy URL a sandbox is configured with, for example
// http://dcx-…:…@host.openshell.internal:18972. The result contains the
// secret; never log it.
func (c Credential) ProxyURL(host string, port int) string {
	u := url.URL{
		Scheme: "http",
		User:   url.UserPassword(c.Username, c.Password),
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
	}
	return u.String()
}

// String redacts the password so a credential never leaks through %v.
func (c Credential) String() string { return c.Username + ":<redacted>" }

// GoString redacts the password so a credential never leaks through %#v.
func (c Credential) GoString() string { return "egress.Credential{" + c.String() + "}" }

// CredentialStore is an in-memory Authenticator. It keeps only SHA-256
// digests of passwords and at most one credential per binding, so
// registering a new credential for a binding rotates (revokes) the old one.
type CredentialStore struct {
	mu        sync.RWMutex
	byUser    map[string]storedCredential
	byBinding map[string]string
}

type storedCredential struct {
	digest    [sha256.Size]byte
	principal Principal
	// suspended is the refusal of a suspended credential (Suspend), nil
	// while it authenticates.
	suspended *Decision
}

// dummyDigest keeps the unknown-username path doing the same comparison work
// as the known-username path.
var dummyDigest = sha256.Sum256([]byte("defenseclaw-egress-unknown-user"))

// NewCredentialStore returns an empty store.
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{byUser: map[string]storedCredential{}, byBinding: map[string]string{}}
}

// Register installs c for p, replacing any credential previously registered
// for p.BindingID. Re-registering the same credential updates the principal
// (for example a profile change) without rotating. Open tunnels follow
// either change once Proxy.Recheck runs.
func (s *CredentialStore) Register(c Credential, p Principal) error {
	return s.store(c, p, nil)
}

// Suspend registers c for p like Register, but refuses it: Authenticate
// rejects it, and the proxy answers the sandbox's requests with why (a 403
// whose body names the reason, and a blocked event) instead of the 407
// challenge an unknown credential gets. It is for a sandbox whose policy
// turns its web egress off while it runs, so neither its agent nor its user
// goes debugging proxy credentials that are fine. Register lifts it, and
// Revoke drops the credential; Proxy.Recheck ends the open tunnels. why
// needs Category and Reason; Host and Port are taken from each request.
func (s *CredentialStore) Suspend(c Credential, p Principal, why Decision) error {
	if why.Category == "" || strings.TrimSpace(why.Reason) == "" {
		return fmt.Errorf("%w: a suspension needs a category and a reason", ErrInvalidCredential)
	}
	why.Allowed, why.Unblockable = false, false
	return s.store(c, p, &why)
}

func (s *CredentialStore) store(c Credential, p Principal, suspended *Decision) error {
	if err := validateCredential(c); err != nil {
		return err
	}
	if strings.TrimSpace(p.BindingID) == "" {
		return fmt.Errorf("%w: principal has no binding id", ErrInvalidCredential)
	}
	if p.Mode != "" && !p.Mode.valid() {
		return fmt.Errorf("%w: unknown mode %q", ErrInvalidCredential, p.Mode)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.byUser[c.Username]; ok && existing.principal.BindingID != p.BindingID {
		return ErrCredentialInUse
	}
	if old, ok := s.byBinding[p.BindingID]; ok && old != c.Username {
		delete(s.byUser, old)
	}
	s.byUser[c.Username] = storedCredential{digest: sha256.Sum256([]byte(c.Password)), principal: p, suspended: suspended}
	s.byBinding[p.BindingID] = c.Username
	return nil
}

// Suspended implements SuspendingAuthenticator: the principal and refusal
// of a suspended credential whose secret matches.
func (s *CredentialStore) Suspended(username, password string) (Principal, Decision, bool) {
	digest := sha256.Sum256([]byte(password))
	s.mu.RLock()
	stored, ok := s.byUser[username]
	s.mu.RUnlock()
	if !ok || stored.suspended == nil || subtle.ConstantTimeCompare(digest[:], stored.digest[:]) != 1 {
		return Principal{}, Decision{}, false
	}
	return stored.principal, *stored.suspended, true
}

// Revoke removes the credential registered for bindingID and reports
// whether there was one. Tunnels and requests already open stay open until
// Proxy.Recheck closes them.
func (s *CredentialStore) Revoke(bindingID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.byBinding[bindingID]
	if !ok {
		return false
	}
	delete(s.byBinding, bindingID)
	delete(s.byUser, user)
	return true
}

// Lookup returns the principal registered for bindingID; a suspended
// credential (Suspend) has none.
func (s *CredentialStore) Lookup(bindingID string) (Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.byBinding[bindingID]
	if !ok || s.byUser[user].suspended != nil {
		return Principal{}, false
	}
	return s.byUser[user].principal, true
}

// Len returns the number of registered credentials.
func (s *CredentialStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byUser)
}

// Authenticate implements Authenticator.
func (s *CredentialStore) Authenticate(username, password string) (Principal, bool) {
	digest := sha256.Sum256([]byte(password))
	s.mu.RLock()
	stored, ok := s.byUser[username]
	s.mu.RUnlock()
	if !ok {
		subtle.ConstantTimeCompare(digest[:], dummyDigest[:])
		return Principal{}, false
	}
	if subtle.ConstantTimeCompare(digest[:], stored.digest[:]) != 1 || stored.suspended != nil {
		return Principal{}, false
	}
	return stored.principal, true
}

func validateCredential(c Credential) error {
	if len(c.Username) == 0 || len(c.Username) > maxCredentialUserLen {
		return fmt.Errorf("%w: username must be 1-%d characters", ErrInvalidCredential, maxCredentialUserLen)
	}
	for i := 0; i < len(c.Username); i++ {
		if !isUnreservedURLByte(c.Username[i]) {
			return fmt.Errorf("%w: username may only contain URL-unreserved characters", ErrInvalidCredential)
		}
	}
	if len(c.Password) < minCredentialPassLen || len(c.Password) > maxCredentialPassLen {
		return fmt.Errorf("%w: password must be %d-%d characters", ErrInvalidCredential, minCredentialPassLen, maxCredentialPassLen)
	}
	for i := 0; i < len(c.Password); i++ {
		if c.Password[i] < 0x21 || c.Password[i] > 0x7e {
			return fmt.Errorf("%w: password must be printable ASCII without spaces", ErrInvalidCredential)
		}
	}
	return nil
}

func isUnreservedURLByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// parseProxyAuthorization extracts Basic credentials from the
// Proxy-Authorization header values. Exactly one header is accepted; other
// schemes, malformed base64 and values without a colon are rejected.
func parseProxyAuthorization(values []string) (username, password string, ok bool) {
	if len(values) != 1 {
		return "", "", false
	}
	scheme, blob, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !found || !strings.EqualFold(scheme, "basic") {
		return "", "", false
	}
	blob = strings.TrimSpace(blob)
	if blob == "" || len(blob) > maxProxyAuthorizationLen {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", "", false
	}
	username, password, found = strings.Cut(string(decoded), ":")
	if !found || username == "" {
		return "", "", false
	}
	return username, password, true
}
