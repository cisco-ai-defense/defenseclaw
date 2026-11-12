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

package extproc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/secretshape"
)

// Finding kinds, also refusal categories when a finding refuses.
const (
	findSecretInURL        = "secret_in_url"
	findSecretInHeader     = "secret_in_header"
	findSecretInCredential = "secret_in_credential_header"
	findSecretInBody       = "secret_in_body"
	findActorSecret        = "actor_secret"
	findPlaceholderUnbound = "placeholder_unbound"
)

// credentialHeaders carry a credential by convention. Their values are
// always redacted; a secret shape in one is the actor holding a credential
// (an alert by default, DLPConfig.CredentialHeaders), not a leak in data.
var credentialHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "x-api-key": true, "api-key": true,
	"x-auth-token": true, "x-access-token": true, "cookie": true, "x-amz-security-token": true,
	"x-goog-api-key": true, "private-token": true, "x-github-token": true,
}

// actorJWTHeader is the header the EgressPolicy fills with the actor JWT on
// the DefenseClaw host. Anywhere else its value is the actor's own, and a
// JWT in it is a token sent off the cluster.
const actorJWTHeader = "x-defenseclaw-actor"

// finding is one DLP observation. where is "url", "body" or "header:<name>";
// label is the shape or the secret's configured name, never a value.
type finding struct {
	kind  string
	where string
	label string
	deny  bool
}

func (f finding) String() string {
	s := f.kind + "@" + f.where
	if f.label != "" {
		s += "(" + f.label + ")"
	}
	return s
}

// binding is a compiled SecretBinding.
type binding struct {
	name        string
	hosts       *hostMatcher
	header      string
	placeholder string
}

func compileBindings(in []SecretBinding) []binding {
	out := make([]binding, 0, len(in))
	for _, s := range in {
		out = append(out, binding{name: s.Name, hosts: mustHostMatcher(s.Hosts),
			header: strings.ToLower(strings.TrimSpace(s.Header)), placeholder: s.Placeholder})
	}
	return out
}

// injectedHeader reports a header that carries a bound secret's real value
// on this host: Substrate replaced the placeholder there.
func injectedHeader(bs []binding, host, header string) bool {
	for _, b := range bs {
		if b.header == header {
			if _, ok := b.hosts.match(host); ok {
				return true
			}
		}
	}
	return false
}

// unboundPlaceholder returns the binding whose placeholder s carries to a
// host it is not bound to.
func unboundPlaceholder(bs []binding, host, s string) (string, bool) {
	for _, b := range bs {
		if b.placeholder == "" || !strings.Contains(s, b.placeholder) {
			continue
		}
		if _, ok := b.hosts.match(host); !ok {
			return b.name, true
		}
	}
	return "", false
}

// minExactValueLen keeps short values from matching everywhere.
const minExactValueLen = 8

// secretValues reads the actor_secrets values from a mounted Secret
// directory, one file per name, and keeps the forms a value is matched in:
// as is, base64 (standard and URL alphabets, with and without padding) and
// URL-encoded. Files are read again when they change (rotation needs no
// restart). Values never leave this type.
type secretValues struct {
	dir     string
	refresh time.Duration
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]secretFile
}

type secretFile struct {
	checked time.Time
	mod     time.Time
	size    int64
	forms   []string
}

func newSecretValues(dir string) *secretValues {
	return &secretValues{dir: dir, refresh: 5 * time.Second, now: time.Now, cache: map[string]secretFile{}}
}

func (s *secretValues) forms(name string) []string {
	if s == nil || s.dir == "" || !validSecretFileName(name) {
		return nil
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.cache[name]
	if ok && now.Sub(f.checked) < s.refresh {
		return f.forms
	}
	file := filepath.Join(s.dir, name)
	st, err := os.Stat(file)
	if err != nil {
		delete(s.cache, name)
		return nil
	}
	if ok && st.ModTime().Equal(f.mod) && st.Size() == f.size {
		f.checked = now
		s.cache[name] = f
		return f.forms
	}
	data, err := os.ReadFile(file)
	if err != nil || len(data) > 64<<10 {
		delete(s.cache, name)
		return nil
	}
	s.cache[name] = secretFile{checked: now, mod: st.ModTime(), size: st.Size(), forms: valueForms(strings.TrimSpace(string(data)))}
	return s.cache[name].forms
}

func valueForms(v string) []string {
	if len(v) < minExactValueLen {
		return nil
	}
	b := []byte(v)
	seen := map[string]bool{}
	var out []string
	for _, f := range []string{v, base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b), url.QueryEscape(v), url.PathEscape(v)} {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// exactValue returns the name of the first actor secret whose value is in s.
func (s *secretValues) exactValue(names []string, texts ...string) (string, bool) {
	for _, n := range names {
		for _, form := range s.forms(n) {
			for _, t := range texts {
				if strings.Contains(t, form) {
					return n, true
				}
			}
		}
	}
	return "", false
}

// decodedVariants returns s and up to two rounds of URL decoding, so a
// secret percent-encoded once or twice is still seen.
func decodedVariants(s string) []string {
	out := []string{s}
	cur := s
	for i := 0; i < 2; i++ {
		next, err := url.QueryUnescape(cur)
		if err != nil {
			next, err = url.PathUnescape(cur)
		}
		if err != nil || next == cur {
			break
		}
		out = append(out, next)
		cur = next
	}
	return out
}

// findShape returns the first secret shape in any of the variants.
func findShape(vars []string) (secretshape.InlineSecret, bool) {
	for _, v := range vars {
		if sec, ok := secretshape.FindInlineSecret(v); ok {
			return sec, true
		}
	}
	return secretshape.InlineSecret{}, false
}

// jsonStrings returns the string keys and values of a JSON document,
// unescaped, one per line; ok is false when body is not JSON.
func jsonStrings(body []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return b.String(), true
		}
		if err != nil {
			return "", false
		}
		if s, ok := tok.(string); ok {
			b.WriteString(s)
			b.WriteByte(0x0a)
		}
	}
}

// scanURL scans :path (path and query) for secret shapes, actor secrets and
// unbound placeholders.
func (e *Engine) scanURL(req *Request, pol *Policy) []finding {
	vars := decodedVariants(req.Path)
	var out []finding
	if sec, ok := findShape(vars); ok {
		out = append(out, finding{kind: findSecretInURL, where: "url", label: sec.Label, deny: true})
	}
	if name, ok := e.secrets.exactValue(pol.actorSecrets, vars...); ok {
		out = append(out, finding{kind: findActorSecret, where: "url", label: name, deny: true})
	}
	if name, ok := unboundPlaceholder(e.bindings, req.Host, req.Path); ok {
		out = append(out, finding{kind: findPlaceholderUnbound, where: "url", label: name})
	}
	return out
}

// scanHeaders scans every regular header. A bound secret's header on one of
// its hosts carries the injected value and is skipped.
func (e *Engine) scanHeaders(req *Request, pol *Policy) []finding {
	var out []finding
	for _, h := range req.Headers {
		if strings.HasPrefix(h.Name, ":") || injectedHeader(e.bindings, req.Host, h.Name) {
			continue
		}
		where := "header:" + safeHeaderName(h.Name)
		vars := decodedVariants(h.Value)
		if name, ok := e.secrets.exactValue(pol.actorSecrets, vars...); ok {
			out = append(out, finding{kind: findActorSecret, where: where, label: name, deny: true})
			continue
		}
		if name, ok := unboundPlaceholder(e.bindings, req.Host, h.Value); ok {
			out = append(out, finding{kind: findPlaceholderUnbound, where: where, label: name})
		}
		sec, ok := findShape(vars)
		if !ok {
			continue
		}
		if credentialHeaders[h.Name] {
			out = append(out, finding{kind: findSecretInCredential, where: where, label: sec.Label, deny: e.cfg.DLP.CredentialHeaders == dlpDeny})
			continue
		}
		out = append(out, finding{kind: findSecretInHeader, where: where, label: sec.Label, deny: true})
	}
	return out
}

// scanBody scans an inspected body in the same decode set as the URL and
// headers (GAP-0064): as sent, its JSON string values unescaped (so a
// \u-escaped secret is seen), and each URL-decoded up to twice.
func (e *Engine) scanBody(req *Request, pol *Policy, body []byte) []finding {
	text := string(body)
	vars := decodedVariants(text)
	if js, ok := jsonStrings(body); ok && js != text {
		vars = append(vars, decodedVariants(js)...)
	}
	var out []finding
	if sec, ok := findShape(vars); ok {
		out = append(out, finding{kind: findSecretInBody, where: "body", label: sec.Label, deny: true})
	}
	if name, ok := e.secrets.exactValue(pol.actorSecrets, vars...); ok {
		out = append(out, finding{kind: findActorSecret, where: "body", label: name, deny: true})
	}
	if name, ok := unboundPlaceholder(e.bindings, req.Host, text); ok {
		out = append(out, finding{kind: findPlaceholderUnbound, where: "body", label: name})
	}
	return out
}

// safeHeaderName bounds a header name for a rule or a log: token characters
// only, at most 64 bytes.
func safeHeaderName(n string) string {
	var b strings.Builder
	for i := 0; i < len(n) && b.Len() < 64; i++ {
		c := n[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteByte(c)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}
