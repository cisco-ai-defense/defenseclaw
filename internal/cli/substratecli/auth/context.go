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
	"strconv"
	"strings"
)

// Context is one cluster the launcher talks to. It holds no secret.
// Keys a context file holds that are not here (router_url,
// router_ca_file, router_cert_file, router_key_file and relay_port from
// earlier builds) are ignored on load and dropped on the next save.
type Context struct {
	AdminURL     string   `json:"admin_url"`
	AdminCAFile  string   `json:"admin_ca_file,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	IssuerCAFile string   `json:"issuer_ca_file,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	// WorkloadAudience is the audience a CI workload token must carry
	// (default DefaultWorkloadAudience); GitHub Actions is asked for it.
	WorkloadAudience string `json:"workload_audience,omitempty"`
	// Profile and Template are what run uses when it is given none.
	Profile  string `json:"profile,omitempty"`
	Template string `json:"template,omitempty"`
	// Kube selects the Kubernetes identity (an install without an OIDC
	// provider): the bearer is the credential of a kubeconfig user and
	// the gateway checks it with a TokenReview. The issuer fields are
	// then ignored.
	Kube bool `json:"kube,omitempty"`
	// Kubeconfig is the kubeconfig file; empty follows the standard
	// rules ($KUBECONFIG list, then ~/.kube/config).
	Kubeconfig string `json:"kubeconfig,omitempty"`
	// KubeContext is the kubeconfig context; empty is its current-context.
	KubeContext string `json:"kube_context,omitempty"`
	// KubeNamespace is where the cluster publishes its launcher endpoint
	// record (default DefaultKubeNamespace).
	KubeNamespace string `json:"kube_namespace,omitempty"`
	// KubePinServer and KubePinAdminURL are what login --kube verified:
	// the kubeconfig cluster's API server and the admin URL it publishes.
	// The kube bearer is handed out only while both still match.
	KubePinServer   string `json:"kube_pin_server,omitempty"`
	KubePinAdminURL string `json:"kube_pin_admin_url,omitempty"`
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
// environment overrides for admin URL, issuer, client ID, workload
// audience and DEFENSECLAW_SUBSTRATE_KUBE. With no context file at all,
// DEFENSECLAW_SUBSTRATE_ADMIN_URL alone gives a context named "default"
// (CI).
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
			return "", Context{}, fmt.Errorf("no substrate context is set up; %s --admin-url URL --issuer URL --client-id ID (or --admin-url URL --kube on a cluster without an OIDC provider)", loginHint)
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
	}{{EnvAdminURL, &c.AdminURL}, {EnvIssuer, &c.Issuer}, {EnvClientID, &c.ClientID}, {EnvWorkloadAudience, &c.WorkloadAudience}} {
		if v := strings.TrimSpace(env(o.env)); v != "" {
			*o.dst = v
		}
	}
	if v := strings.TrimSpace(env(EnvKube)); v != "" {
		on, err := strconv.ParseBool(v)
		if err != nil {
			return "", Context{}, fmt.Errorf("%s=%q is not valid; use 1 or 0", EnvKube, clean(v, 20))
		}
		c.Kube = on
	}
	if err := c.Validate(false); err != nil {
		return "", Context{}, fmt.Errorf("substrate context %q: %w", name, err)
	}
	return name, c, nil
}

// Validate checks the context. needIssuer also requires the issuer and
// client ID (a person sign-in needs both; a workload token needs neither).
// A kube context needs only admin_url: its issuer fields are ignored.
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
	if strings.ContainsAny(c.Kubeconfig, "\r\n\x00") {
		errs = append(errs, "kubeconfig must be one file path")
	}
	if k := c.KubeContext; k != "" && (strings.TrimSpace(k) != k || strings.ContainsAny(k, "\r\n\t\x00")) {
		errs = append(errs, fmt.Sprintf("kube_context %q is not valid: use the context name as kubectl config get-contexts shows it", clean(k, 80)))
	}
	if c.KubeNamespace != "" {
		add(checkKubeNamespace(c.KubeNamespace))
	}
	if c.Kube {
		if len(errs) > 0 {
			return errors.New(strings.Join(errs, "; "))
		}
		return nil
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
	if a := c.WorkloadAudience; a != "" && (strings.TrimSpace(a) == "" || strings.ContainsAny(a, " \t\r\n")) {
		errs = append(errs, fmt.Sprintf("workload_audience %q is not valid: use the one audience the cluster trusts for CI tokens, with no spaces", clean(a, 80)))
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
