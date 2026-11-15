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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/secretshape"
)

// Redactor makes request data safe to log. Credential headers, the actor
// JWT header, configured secret headers and extra names are replaced by the
// redaction placeholder (redaction.ForSinkString, which ignores the reveal
// switch); every other value has placeholders, actor secret values and
// secret shapes cut out of it.
type Redactor struct {
	names        map[string]bool
	placeholders []string
	secrets      *secretValues
	secretNames  []string
}

func newRedactor(cfg *Config, secrets *secretValues) *Redactor {
	r := &Redactor{names: map[string]bool{actorJWTHeader: true}, secrets: secrets}
	for n := range credentialHeaders {
		r.names[n] = true
	}
	for _, n := range cfg.RedactHeaders {
		r.names[strings.ToLower(strings.TrimSpace(n))] = true
	}
	for _, s := range cfg.Secrets {
		r.names[strings.ToLower(strings.TrimSpace(s.Header))] = true
		if s.Placeholder != "" {
			r.placeholders = append(r.placeholders, s.Placeholder)
		}
	}
	seen := map[string]bool{}
	for _, p := range cfg.Profiles {
		for _, n := range p.ActorSecrets {
			if !seen[n] {
				seen[n] = true
				r.secretNames = append(r.secretNames, n)
			}
		}
	}
	return r
}

// Header returns value as it may be logged under name.
func (r *Redactor) Header(name, value string) string {
	if r.names[strings.ToLower(name)] {
		return redaction.ForSinkString(value)
	}
	return r.Scrub(value)
}

// Headers returns the redacted map of hs (pseudo-headers included, :path
// without its query).
func (r *Redactor) Headers(hs []Header) map[string]string {
	out := make(map[string]string, len(hs))
	for _, h := range hs {
		v := h.Value
		if h.Name == ":path" {
			v = r.Path(v)
		} else {
			v = r.Header(h.Name, v)
		}
		key := safeHeaderName(h.Name)
		if strings.HasPrefix(h.Name, ":") {
			key = ":" + safeHeaderName(h.Name[1:])
		}
		out[key] = v
	}
	return out
}

// Path is a request path for a log: the query dropped, the rest scrubbed.
func (r *Redactor) Path(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if len(p) > 512 {
		p = p[:512]
	}
	return r.Scrub(p)
}

// Scrub cuts placeholders, actor secret values and secret shapes out of s.
func (r *Redactor) Scrub(s string) string {
	if s == "" {
		return s
	}
	for _, p := range r.placeholders {
		s = strings.ReplaceAll(s, p, "<placeholder>")
	}
	for _, n := range r.secretNames {
		for _, f := range r.secrets.forms(n) {
			s = strings.ReplaceAll(s, f, "<redacted actor_secret>")
		}
	}
	for i := 0; i < 32; i++ {
		sec, ok := secretshape.FindInlineSecret(s)
		if !ok {
			break
		}
		end := secretEnd(s, sec)
		s = s[:sec.Offset] + redaction.ForSinkString(s[sec.Offset:end]) + s[end:]
	}
	return s
}

// secretEnd is where the secret found at sec.Offset ends: the end of a PEM
// block, or the next delimiter.
func secretEnd(s string, sec secretshape.InlineSecret) int {
	if sec.Label == "private-key" {
		if i := strings.Index(s[sec.Offset:], "-----END"); i >= 0 {
			rest := sec.Offset + i + len("-----END")
			if j := strings.Index(s[rest:], "-----"); j >= 0 {
				return rest + j + len("-----")
			}
		}
		return len(s)
	}
	for i := sec.Offset; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n', '"', '\'', '&', ';', ',', '<', '>', '?', '#', '/', '\\', '=':
			return i
		}
	}
	return len(s)
}
