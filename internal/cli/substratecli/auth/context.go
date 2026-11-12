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

package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Context is one cluster the launcher talks to. It holds no secret.
type Context struct {
	AdminURL         string   `json:"admin_url"`
	AdminCAFile      string   `json:"admin_ca_file,omitempty"`
	Issuer           string   `json:"issuer,omitempty"`
	IssuerCAFile     string   `json:"issuer_ca_file,omitempty"`
	ClientID         string   `json:"client_id,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	RouterURL        string   `json:"router_url,omitempty"`
	RouterCAFile     string   `json:"router_ca_file,omitempty"`
	RouterCertFile   string   `json:"router_cert_file,omitempty"`
	RouterKeyFile    string   `json:"router_key_file,omitempty"`
	RelayPort        int      `json:"relay_port,omitempty"`
	WorkloadAudience string   `json:"workload_audience,omitempty"`
	// Profile and Template are what run uses when it is given none.
	Profile  string `json:"profile,omitempty"`
	Template string `json:"template,omitempty"`
}

// ContextFile is <StateDir>/substrate/contexts.json.
type ContextFile struct {
	Current  string             `json:"current"`
	Contexts map[string]Context `json:"contexts"`
}

// LoadContexts reads the context file. A missing file is an empty set.
func LoadContexts() (*ContextFile, error) {
	p := ContextsPath()
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return &ContextFile{Contexts: map[string]Context{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the substrate contexts: %w", err)
	}
	var f ContextFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON; fix or remove it, then %s", p, loginHint)
	}
	if f.Contexts == nil {
		f.Contexts = map[string]Context{}
	}
	return &f, nil
}

// Save writes the context file atomically, mode 0600 in a 0700 directory.
func (f *ContextFile) Save() error {
	for name := range f.Contexts {
		if err := ValidName(name); err != nil {
			return err
		}
	}
	if f.Current != "" {
		if _, ok := f.Contexts[f.Current]; !ok {
			return fmt.Errorf("the current context %q is not in the context file", f.Current)
		}
	}
	out := *f
	if out.Contexts == nil {
		out.Contexts = map[string]Context{}
	}
	b, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(ContextsPath(), append(b, '\n'))
}

// ResolveContext picks the context: the flag, else
// DEFENSECLAW_SUBSTRATE_CONTEXT, else the current one; then applies the
// environment overrides for admin URL, issuer, client ID and router URL.
// With no context file at all, DEFENSECLAW_SUBSTRATE_ADMIN_URL alone gives
// a context named "default" (CI).
func ResolveContext(flagName string) (string, Context, error) {
	return resolveContext(flagName, os.Getenv)
}

func resolveContext(flagName string, env func(string) string) (string, Context, error) {
	f, err := LoadContexts()
	if err != nil {
		return "", Context{}, err
	}
	name, from := strings.TrimSpace(flagName), "the --context flag"
	if name == "" {
		name, from = strings.TrimSpace(env(EnvContext)), EnvContext
	}
	if name == "" {
		name, from = f.Current, "the current context"
	}
	c, ok := Context{}, false
	if name != "" {
		c, ok = f.Contexts[name]
	}
	if !ok {
		switch {
		case strings.TrimSpace(env(EnvAdminURL)) != "":
			if name == "" {
				name = "default"
			}
		case name == "":
			return "", Context{}, fmt.Errorf("no substrate context is set up; %s --admin-url URL --issuer URL --client-id ID", loginHint)
		default:
			return "", Context{}, fmt.Errorf("substrate context %q (from %s) does not exist; %s --context %s --admin-url URL --issuer URL --client-id ID", name, from, loginHint, name)
		}
	}
	if err := ValidName(name); err != nil {
		return "", Context{}, err
	}
	for _, o := range []struct {
		env string
		dst *string
	}{{EnvAdminURL, &c.AdminURL}, {EnvIssuer, &c.Issuer}, {EnvClientID, &c.ClientID}, {EnvRouterURL, &c.RouterURL}} {
		if v := strings.TrimSpace(env(o.env)); v != "" {
			*o.dst = v
		}
	}
	if err := c.Validate(false); err != nil {
		return "", Context{}, fmt.Errorf("substrate context %q: %w", name, err)
	}
	return name, c, nil
}

// Validate checks the context. needIssuer also requires the issuer and
// client ID (a person sign-in needs both; a workload token needs neither).
func (c Context) Validate(needIssuer bool) error {
	var errs []string
	add := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if strings.TrimSpace(c.AdminURL) == "" {
		errs = append(errs, "admin_url is not set (use --admin-url URL or "+EnvAdminURL+")")
	} else {
		add(checkURL("admin_url", c.AdminURL, false))
	}
	switch {
	case strings.TrimSpace(c.Issuer) != "":
		add(checkURL("issuer", c.Issuer, false))
	case needIssuer:
		errs = append(errs, "issuer is not set (use --issuer URL or "+EnvIssuer+")")
	}
	if needIssuer && strings.TrimSpace(c.ClientID) == "" {
		errs = append(errs, "client_id is not set (use --client-id ID or "+EnvClientID+")")
	}
	if c.RouterURL != "" {
		add(checkURL("router_url", c.RouterURL, false))
	}
	if c.RelayPort < 0 || c.RelayPort > 65535 {
		errs = append(errs, fmt.Sprintf("relay_port %d is not a TCP port (1-65535)", c.RelayPort))
	}
	if (c.RouterCertFile == "") != (c.RouterKeyFile == "") {
		errs = append(errs, "router_cert_file and router_key_file must be set together")
	}
	for _, s := range c.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n") {
			errs = append(errs, fmt.Sprintf("scope %q is not valid (one word per scope)", s))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// checkURL enforces https (http only for localhost, 127.0.0.1 and ::1),
// a host, and no credentials. The URL itself is not echoed on a parse
// failure, so a mistyped secret never reaches an error.
func checkURL(field, raw string, allowQuery bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%s is not a valid URL", field)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not carry a user name or password", field)
	}
	if u.Host == "" {
		return fmt.Errorf("%s needs a host, as in https://HOST[:PORT]", field)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("%s must use https (http is allowed only for localhost, 127.0.0.1 and ::1)", field)
		}
	default:
		return fmt.Errorf("%s must be an https URL", field)
	}
	if u.Fragment != "" || (!allowQuery && u.RawQuery != "") {
		return fmt.Errorf("%s must not have a query or fragment", field)
	}
	return nil
}

func isLoopbackHost(h string) bool {
	switch strings.ToLower(h) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// writeFileAtomic writes data with mode 0600 through a temp file and a
// rename, creating the parent with mode 0700.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(dir, 0o700)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("write in %s: %w", dir, err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	ok = true
	return nil
}
