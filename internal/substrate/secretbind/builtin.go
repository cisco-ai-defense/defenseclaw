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

package secretbind

import (
	"encoding/base64"
	"errors"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/egressspec"
)

// Header forms of a template (substrate.secret_templates[].form).
const (
	FormBearer = "bearer"
	FormBasic  = "basic"
	FormRaw    = "raw"
)

// Template is one admin-approved way to bind a person's own secret: which
// hosts it covers without an administrator, which header the value goes
// in and in which form.
type Template struct {
	Name      string   `json:"name"`
	Hosts     []string `json:"hosts"`
	Header    string   `json:"header"`
	Form      string   `json:"form"`
	BasicUser string   `json:"basic_user,omitempty"`
	Profiles  []string `json:"profiles"`
	Registry  string   `json:"registry"`
}

// Builtin is the default catalog (B1 2.5, D1-3): public hosts only, and
// the generic templates cover no host, so every use of them is an
// administrator ask.
func Builtin() []Template {
	t := func(name, form, user, registry string, hosts ...string) Template {
		return Template{Name: name, Hosts: hosts, Header: "Authorization", Form: form, BasicUser: user,
			Profiles: []string{"*"}, Registry: registry}
	}
	return []Template{
		t("github", FormBasic, "x-access-token", "none", "github.com", "api.github.com"),
		t("gitlab", FormBasic, "oauth2", "none", "gitlab.com"),
		t("bitbucket", FormBasic, "x-token-auth", "none", "bitbucket.org", "api.bitbucket.org"),
		t("npm", FormBearer, "", "npm", "registry.npmjs.org"),
		t("pypi", FormBasic, "__token__", "pypi", "upload.pypi.org"),
		t("generic-bearer", FormBearer, "", "none"),
		t("generic-basic", FormBasic, "", "none"),
	}
}

// Catalog is the effective template list: the built-in seven when the
// admin lists none, else the admin's list, where an entry named like a
// built-in takes the built-in's unset fields.
func Catalog(admin []config.SubstrateSecretTemplate) []Template {
	builtin := Builtin()
	if len(admin) == 0 {
		return builtin
	}
	out := make([]Template, 0, len(admin))
	for _, a := range admin {
		t := Template{Name: a.Name, Profiles: []string{"*"}, Header: "Authorization", Form: FormBearer, Registry: "none"}
		for _, b := range builtin {
			if b.Name == a.Name {
				t = b
			}
		}
		if a.Hosts != nil {
			t.Hosts = append([]string(nil), a.Hosts...)
		}
		if a.Header != "" {
			t.Header = a.Header
		}
		if a.Form != "" {
			t.Form = a.Form
		}
		if a.BasicUser != "" {
			t.BasicUser = a.BasicUser
		}
		if len(a.Profiles) > 0 {
			t.Profiles = append([]string(nil), a.Profiles...)
		}
		if a.Registry != "" {
			t.Registry = a.Registry
		}
		out = append(out, t)
	}
	return out
}

// Find returns the template named name.
func Find(catalog []Template, name string) (Template, bool) {
	for _, t := range catalog {
		if t.Name == name {
			return t, true
		}
	}
	return Template{}, false
}

// Covers reports whether host (an exact name or *.domain) lies inside one
// of the template's host patterns: such a binding needs no administrator.
func (t Template) Covers(host string) bool {
	h, ok := egressspec.ParsePattern(host)
	if !ok || h.Any {
		return false
	}
	for _, raw := range t.Hosts {
		p, ok := egressspec.ParsePattern(raw)
		if !ok {
			continue
		}
		switch {
		case p.Any:
			return true
		case !p.Wildcard:
			if !h.Wildcard && h.Name == p.Name {
				return true
			}
		case h.Wildcard:
			if h.Name == p.Name {
				return true
			}
		default:
			if label, ok := strings.CutSuffix(h.Name, "."+p.Name); ok && label != "" && !strings.Contains(label, ".") {
				return true
			}
		}
	}
	return false
}

// ForProfile reports whether people of profile may use the template.
func (t Template) ForProfile(profile string) bool {
	for _, g := range t.Profiles {
		if ok, err := path.Match(g, profile); err == nil && ok {
			return true
		}
	}
	return false
}

// Prefix is the text Substrate puts before the stored value in the header.
// For basic the launcher stores base64(user:token), so the value is the
// whole credential after "Basic ".
func (t Template) Prefix() string {
	switch t.Form {
	case FormBearer:
		return "Bearer "
	case FormBasic:
		return "Basic "
	}
	return ""
}

// FormStamp names how StoredValue forms a value for b under t: the form,
// and for basic the user. A binding keeps the stamp of its stored value, so
// a later template edit that changes it can be flagged (RV3 P4-3).
func (t Template) FormStamp(b Binding) string {
	if t.Form == FormBasic {
		user := b.BasicUser
		if user == "" {
			user = t.BasicUser
		}
		return FormBasic + ":" + user
	}
	if t.Form == "" {
		return FormRaw
	}
	return t.Form
}

// StoredValue is what the launcher stores for token under t for binding
// b. For basic it is base64(user:token), with the user from the binding
// (generic-basic takes it at add) or else the template; Substrate puts
// "Basic " before it. Any other form stores the token as given. Add and
// set both store through it, so a re-set keeps the injected header valid.
func (t Template) StoredValue(b Binding, token string) (string, error) {
	stored := token
	if t.Form == FormBasic {
		user := b.BasicUser
		if user == "" {
			user = t.BasicUser
		}
		if !basicUserRE.MatchString(user) {
			return "", errors.New("basic_user")
		}
		stored = base64.StdEncoding.EncodeToString([]byte(user + ":" + token))
	}
	if len(stored) > MaxStoredValue {
		return "", errors.New("value too large for a request header")
	}
	return stored, nil
}

// MaxStoredValue caps the stored (header) form of a value: the proxy's
// default request header limit is 60 KiB in all, and the basic form grows
// a token by 4/3 (RV3 P4-2). A larger value would fail every request.
const MaxStoredValue = 56 << 10

// ValueSecretName is the Kubernetes Secret, in the self-service
// namespace, that holds every value of the person with key personKey; one
// key per binding id.
func ValueSecretName(personKey string) string { return "dc-b-" + personKey }

// SourceFor is the ate-secret source of binding b's value. It keeps the
// person placeholder, so the controller resolves it with the actor's own
// person: even a binding merged into the wrong actor could only name that
// actor's person's Secret.
func SourceFor(provider, namespace string, b Binding) string {
	return "ate-secret://k8s.io/" + provider + "/" + namespace + "/" + ValueSecretName(egressspec.PersonPlaceholder) + "/" + b.ID
}

// SecretFor is binding b, under template t, as a substrate.secrets entry.
// allowEcho is self_service_secrets.allow_echo_bindings.
func SecretFor(t Template, provider, namespace string, b Binding, allowEcho bool) config.SubstrateSecret {
	sec := config.SubstrateSecret{Name: b.Name, Source: SourceFor(provider, namespace, b),
		Scope: egressspec.ScopePerPerson, Profiles: append([]string(nil), t.Profiles...)}
	sec.Inject.Hosts = append([]string(nil), b.Hosts...)
	sec.Inject.Header = t.Header
	sec.Inject.Prefix = t.Prefix()
	sec.Inject.AllowEcho = allowEcho && b.AllowEcho
	return sec
}

// Secrets turns the active, unexpired bindings of one person into
// substrate.secrets entries, as the controller renders them. A binding
// whose template is gone is left out. A binding no administrator approved
// (no ask id) keeps only the hosts its template covers now, so a template
// an administrator narrows later narrows its bindings too (RV3 P2-2); one
// with no host left is left out. An approved binding keeps its host.
func Secrets(catalog []Template, provider, namespace string, bindings []Binding, allowEcho bool, now time.Time) []config.SubstrateSecret {
	var out []config.SubstrateSecret
	for _, b := range bindings {
		if b.State != Active || b.Expired(now) {
			continue
		}
		t, ok := Find(catalog, b.Template)
		if !ok {
			continue
		}
		if b.AskID == "" {
			b.Hosts = slices.DeleteFunc(slices.Clone(b.Hosts), func(h string) bool { return !t.Covers(h) })
			if len(b.Hosts) == 0 {
				continue
			}
		}
		out = append(out, SecretFor(t, provider, namespace, b, allowEcho))
	}
	return out
}
