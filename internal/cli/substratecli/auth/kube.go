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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	kubeExecTimeout  = 30 * time.Second
	kubeNoExpiryKeep = 5 * time.Minute
	kubeStderrMax    = 64 << 10
	kubeExecInfoEnv  = "KUBERNETES_EXEC_INFO"
	kubeExecV1       = "client.authentication.k8s.io/v1"
	kubeExecV1beta1  = "client.authentication.k8s.io/v1beta1"
	kubeCertRefusal  = "certificate sign-in through an exec plugin is not supported by the launcher; use a token-based user, a kubeconfig client certificate or an OIDC cluster"
	// kubeMintSeconds is the life of a ServiceAccount token the launcher
	// mints for the gateway (the TokenRequest minimum is 10 minutes).
	kubeMintSeconds = 900
	// DefaultKubeServiceAccount is the ServiceAccount a client-certificate
	// user signs in as when none is named (the docs create it in the
	// namespace DefenseClaw runs in).
	DefaultKubeServiceAccount = "defenseclaw-launcher"
)

// KubeOptions selects the kubeconfig user whose credential is the bearer
// of a kube context. Every function field has a default: Env os.Getenv,
// RunExec os/exec, ReadFile os.ReadFile, Now time.Now.
type KubeOptions struct {
	// Kubeconfig is one kubeconfig file; empty follows the standard
	// rules ($KUBECONFIG list, then ~/.kube/config).
	Kubeconfig string
	// Context is the kubeconfig context; empty is its current-context.
	Context string
	// Namespace is where DefenseClaw runs (the endpoint record's); a bare
	// ServiceAccount name, and the default one, live there.
	Namespace string
	// ServiceAccount, "NAMESPACE/NAME" or "NAME", makes the launcher hand
	// the gateway a short-lived token it mints for that ServiceAccount
	// (TokenRequest, audience identity.KubeTokenAudience) with the user's
	// own credential. A client-certificate user always does this, with
	// DefaultKubeServiceAccount when none is named: the gateway cannot check
	// a certificate it never sees (GAP-0192).
	ServiceAccount string
	Env            func(string) string
	// RunExec runs an exec credential plugin and returns its stdout. An
	// error's text should be the plugin's stderr (it is cut to one line
	// and token-looking text is blanked before it is shown).
	RunExec  func(ctx context.Context, name string, args []string, env []string, stdin []byte) ([]byte, error)
	ReadFile func(string) ([]byte, error)
	Now      func() time.Time

	execTimeout time.Duration // tests; 0 is kubeExecTimeout
	apiTimeoutT time.Duration // tests; 0 is kubeAPITimeout
}

// KubeOptions builds the kube options of the context.
func (c Context) KubeOptions() KubeOptions {
	return KubeOptions{Kubeconfig: c.Kubeconfig, Context: c.KubeContext, Namespace: c.KubeNamespace, ServiceAccount: c.KubeServiceAccount}
}

func (o KubeOptions) withDefaults() KubeOptions {
	if o.Env == nil {
		o.Env = os.Getenv
	}
	if o.RunExec == nil {
		o.RunExec = runExecDefault
	}
	if o.ReadFile == nil {
		o.ReadFile = os.ReadFile
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.execTimeout <= 0 {
		o.execTimeout = kubeExecTimeout
	}
	return o
}

// KubeLogin reads the kubeconfig (without kubectl) and returns the bearer
// of the selected user: its token, its tokenFile or the answer of its
// exec credential plugin, or a ServiceAccount token it mints (see
// KubeOptions.ServiceAccount). The Token has Kind KindKube and Principal =
// the kubeconfig user name, or system:serviceaccount:NS:NAME for a minted
// one. Nothing is stored. Basic and legacy auth-provider users are refused.
func KubeLogin(ctx context.Context, o KubeOptions) (*Token, error) {
	t, _, err := kubeResolve(ctx, o)
	return t, err
}

// kubeconfig types: only the fields the launcher reads.
type kubeFile struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string      `yaml:"name"`
		Cluster kubeCluster `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string      `yaml:"name"`
		Context kubeContext `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string   `yaml:"name"`
		User kubeUser `yaml:"user"`
	} `yaml:"users"`
}

type kubeCluster struct {
	Server                   string `yaml:"server"`
	TLSServerName            string `yaml:"tls-server-name"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
	CertificateAuthority     string `yaml:"certificate-authority"`
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	ProxyURL                 string `yaml:"proxy-url"`
	DisableCompression       bool   `yaml:"disable-compression"`
}

type kubeContext struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}

type kubeUser struct {
	Token                 string `yaml:"token"`
	TokenFile             string `yaml:"tokenFile"`
	ClientCertificate     string `yaml:"client-certificate"`
	ClientCertificateData string `yaml:"client-certificate-data"`
	ClientKey             string `yaml:"client-key"`
	ClientKeyData         string `yaml:"client-key-data"`
	Username              string `yaml:"username"`
	Password              string `yaml:"password"`
	AuthProvider          *struct {
		Name string `yaml:"name"`
	} `yaml:"auth-provider"`
	Exec *kubeExec `yaml:"exec"`
}

type kubeExec struct {
	APIVersion string   `yaml:"apiVersion"`
	Command    string   `yaml:"command"`
	Args       []string `yaml:"args"`
	Env        []struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	} `yaml:"env"`
	InstallHint        string `yaml:"installHint"`
	ProvideClusterInfo bool   `yaml:"provideClusterInfo"`
	InteractiveMode    string `yaml:"interactiveMode"`
}

// kubeconfig is the merged view; origin is the file that defined an entry
// (relative paths in it are relative to that file's directory).
type kubeconfig struct {
	desc     string
	current  string
	contexts map[string]kubeContext
	users    map[string]kubeUser
	userFrom map[string]string
	clusters map[string]kubeCluster
	clFrom   map[string]string
}

// homeDir follows the usual rules: HOME, on Windows USERPROFILE first.
func homeDir(env func(string) string) string {
	keys := []string{"HOME"}
	if runtime.GOOS == "windows" {
		keys = []string{"USERPROFILE", "HOME"}
	}
	for _, k := range keys {
		if v := strings.TrimSpace(env(k)); v != "" {
			return v
		}
	}
	h, _ := os.UserHomeDir()
	return h
}

func expandHome(p string, env func(string) string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if h := homeDir(env); h != "" {
			return filepath.Join(h, p[1:])
		}
	}
	return p
}

var yamlLineRE = regexp.MustCompile(`line (\d+)`)

// loadKubeconfig reads and merges the kubeconfig files like client-go:
// the first file that sets current-context wins, the first definition of
// a name wins, files of a $KUBECONFIG list that do not exist are skipped.
// No error carries file contents.
func loadKubeconfig(o KubeOptions) (*kubeconfig, error) {
	var paths []string
	listed := false
	kc := &kubeconfig{
		contexts: map[string]kubeContext{}, users: map[string]kubeUser{}, userFrom: map[string]string{},
		clusters: map[string]kubeCluster{}, clFrom: map[string]string{},
	}
	switch {
	case strings.TrimSpace(o.Kubeconfig) != "":
		paths = []string{expandHome(strings.TrimSpace(o.Kubeconfig), o.Env)}
		kc.desc = "the kubeconfig " + paths[0]
	case strings.TrimSpace(o.Env(EnvKubeconfig)) != "":
		for _, p := range filepath.SplitList(o.Env(EnvKubeconfig)) {
			if p = strings.TrimSpace(p); p != "" {
				paths = append(paths, p)
			}
		}
		listed = true
		kc.desc = "the kubeconfig from " + EnvKubeconfig
		if len(paths) == 1 {
			kc.desc = "the kubeconfig " + paths[0]
		}
	default:
		h := homeDir(o.Env)
		if h == "" {
			return nil, fmt.Errorf("cannot find the home directory to read ~/.kube/config; set %s or the context's kubeconfig", EnvKubeconfig)
		}
		paths = []string{filepath.Join(h, ".kube", "config")}
		kc.desc = "the kubeconfig " + paths[0]
	}
	read := 0
	for _, p := range paths {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		b, err := o.ReadFile(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				if listed {
					continue
				}
				return nil, fmt.Errorf("the kubeconfig %s does not exist; point %s or --kubeconfig at the cluster's kubeconfig", p, EnvKubeconfig)
			}
			return nil, fmt.Errorf("the kubeconfig %s cannot be read: %s", p, readReason(err))
		}
		var f kubeFile
		if err := yaml.Unmarshal(b, &f); err != nil {
			where := ""
			if m := yamlLineRE.FindStringSubmatch(err.Error()); m != nil {
				where = " (at line " + m[1] + ")"
			}
			return nil, fmt.Errorf("the kubeconfig %s is not a valid kubeconfig%s; check it with: kubectl config view", p, where)
		}
		read++
		if kc.current == "" {
			kc.current = strings.TrimSpace(f.CurrentContext)
		}
		for _, c := range f.Contexts {
			if _, ok := kc.contexts[c.Name]; c.Name != "" && !ok {
				kc.contexts[c.Name] = c.Context
			}
		}
		for _, u := range f.Users {
			if _, ok := kc.users[u.Name]; u.Name != "" && !ok {
				kc.users[u.Name], kc.userFrom[u.Name] = u.User, p
			}
		}
		for _, c := range f.Clusters {
			if _, ok := kc.clusters[c.Name]; c.Name != "" && !ok {
				kc.clusters[c.Name], kc.clFrom[c.Name] = c.Cluster, p
			}
		}
	}
	if read == 0 {
		return nil, fmt.Errorf("none of the kubeconfig files in %s exist", EnvKubeconfig)
	}
	return kc, nil
}

// readReason is the cause of a file error without the path or contents.
func readReason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return "read error"
}

// relTo resolves a kubeconfig path against the directory of its file.
func relTo(p, origin string) string {
	if p == "" || filepath.IsAbs(p) || origin == "" {
		return p
	}
	return filepath.Join(filepath.Dir(origin), p)
}

// oneToken trims raw and reports whether it is a single bearer token.
func oneToken(raw []byte) (string, bool) {
	t := strings.TrimSpace(string(raw))
	return t, t != "" && len(t) <= maxBody && !strings.ContainsAny(t, " \t\r\n")
}

// kubeSel is the selected kubeconfig context with its user and cluster
// (cluster is nil when the kubeconfig does not define it).
type kubeSel struct {
	kc      *kubeconfig
	name    string
	ctx     kubeContext
	cluster *kubeCluster
	clFrom  string
}

// kubeSelect reads the kubeconfig and picks the context (o has its
// defaults).
func kubeSelect(o KubeOptions) (*kubeSel, error) {
	kc, err := loadKubeconfig(o)
	if err != nil {
		return nil, err
	}
	name, from := strings.TrimSpace(o.Context), "kube_context"
	if name == "" {
		if kc.current == "" {
			return nil, fmt.Errorf("%s has no current-context; pick one with: kubectl config use-context NAME, or give --kube-context NAME", kc.desc)
		}
		name, from = kc.current, "its current-context"
	}
	kctx, ok := kc.contexts[name]
	if !ok {
		return nil, fmt.Errorf("%s has no context %q (named by %s); list them with: kubectl config get-contexts", kc.desc, clean(name, 100), from)
	}
	sel := &kubeSel{kc: kc, name: name, ctx: kctx}
	if c, ok := kc.clusters[kctx.Cluster]; ok {
		sel.cluster, sel.clFrom = &c, kc.clFrom[kctx.Cluster]
	}
	return sel, nil
}

// noCluster says the selected context names a cluster that is not there.
func (s *kubeSel) noCluster() error {
	return fmt.Errorf("the kube context %q names the cluster %q, which %s does not define", clean(s.name, 100), clean(s.ctx.Cluster, 100), s.kc.desc)
}

// kubeResolve returns the bearer of the selected kubeconfig user;
// fromFile says it came from a tokenFile (read again on every call).
func kubeResolve(ctx context.Context, o KubeOptions) (*Token, bool, error) {
	o = o.withDefaults()
	sel, err := kubeSelect(o)
	if err != nil {
		return nil, false, err
	}
	return kubeCredential(ctx, o, sel)
}

// kubeCredential is the bearer the gateway gets for the user of sel: a
// ServiceAccount token minted with the user's own credential when a
// ServiceAccount is named or the user has only a client certificate, else
// the user's own bearer.
func kubeCredential(ctx context.Context, o KubeOptions, sel *kubeSel) (*Token, bool, error) {
	if o.ServiceAccount == "" && !sel.certOnly() {
		return kubeUserCredential(ctx, o, sel)
	}
	bearer := ""
	if !sel.certOnly() {
		own := o
		own.ServiceAccount = ""
		t, _, err := kubeUserCredential(ctx, own, sel)
		if err != nil {
			return nil, false, err
		}
		bearer = t.AccessToken
	}
	t, err := mintKubeToken(ctx, o, sel, bearer)
	return t, false, err
}

// certOnly reports whether the user of sel signs in with a client
// certificate and nothing else.
func (s *kubeSel) certOnly() bool {
	u, ok := s.kc.users[s.ctx.User]
	return ok && u.hasCert() && u.Token == "" && u.TokenFile == "" && u.Exec == nil && u.AuthProvider == nil && u.Username == "" && u.Password == ""
}

func (u kubeUser) hasCert() bool {
	return u.ClientCertificate != "" || u.ClientCertificateData != "" || u.ClientKey != "" || u.ClientKeyData != ""
}

// kubeUserCredential reads the bearer of the user of sel (never a
// certificate).
func kubeUserCredential(ctx context.Context, o KubeOptions, sel *kubeSel) (*Token, bool, error) {
	kc, name, kctx := sel.kc, sel.name, sel.ctx
	if kctx.User == "" {
		return nil, false, fmt.Errorf("the kube context %q names no user", clean(name, 100))
	}
	uname := kctx.User
	u, ok := kc.users[uname]
	if !ok {
		return nil, false, fmt.Errorf("the kube context %q names the user %q, which %s does not define", clean(name, 100), clean(uname, 100), kc.desc)
	}
	who := fmt.Sprintf("the kubeconfig user %q", clean(uname, 100))
	mk := func(tok string, exp time.Time) *Token {
		if exp.IsZero() {
			exp = jwtExpiry(tok)
		}
		return &Token{Kind: KindKube, AccessToken: tok, Expiry: exp, Principal: uname}
	}

	// A tokenFile wins over token (it is read on every use, as in
	// client-go); token is the fallback when the file cannot be read.
	if p := strings.TrimSpace(u.TokenFile); p != "" {
		p = relTo(p, kc.userFrom[uname])
		b, rerr := o.ReadFile(p)
		if rerr == nil {
			if tok, ok := oneToken(b); ok {
				return mk(tok, time.Time{}), true, nil
			}
		}
		if strings.TrimSpace(u.Token) == "" {
			if rerr != nil {
				if errors.Is(rerr, fs.ErrNotExist) {
					return nil, false, fmt.Errorf("the tokenFile of %s (%s) does not exist", who, p)
				}
				return nil, false, fmt.Errorf("the tokenFile of %s (%s) cannot be read: %s", who, p, readReason(rerr))
			}
			return nil, false, fmt.Errorf("the tokenFile of %s (%s) does not hold a single token", who, p)
		}
	}
	if u.Token != "" {
		tok, ok := oneToken([]byte(u.Token))
		if !ok {
			return nil, false, fmt.Errorf("the token of %s is not a single token", who)
		}
		return mk(tok, time.Time{}), false, nil
	}
	if u.Exec != nil {
		if u.Exec.ProvideClusterInfo && sel.cluster == nil {
			return nil, false, fmt.Errorf("the exec plugin of %s asks for the cluster, but %s", who, sel.noCluster())
		}
		tok, exp, err := runKubeExec(ctx, o, who, u.Exec, kc.userFrom[uname], sel.cluster, sel.clFrom)
		if err != nil {
			return nil, false, err
		}
		return mk(tok, exp), false, nil
	}
	if u.AuthProvider != nil {
		return nil, false, fmt.Errorf("%s signs in with the legacy auth-provider %q, which the launcher does not support; switch the user to an exec credential plugin or a token, or use an OIDC cluster", who, clean(u.AuthProvider.Name, 40))
	}
	if u.Username != "" || u.Password != "" {
		return nil, false, fmt.Errorf("%s signs in with a user name and password; the launcher does not support basic sign-in; use a token-based user or an OIDC cluster", who)
	}
	return nil, false, fmt.Errorf("%s has no token, tokenFile or exec plugin; use a token-based user or an OIDC cluster", who)
}

// execInfo is the KUBERNETES_EXEC_INFO ExecCredential.
type execInfo struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Interactive bool         `json:"interactive"`
		Cluster     *execCluster `json:"cluster,omitempty"`
	} `json:"spec"`
}

type execCluster struct {
	Server                   string `json:"server"`
	TLSServerName            string `json:"tls-server-name,omitempty"`
	InsecureSkipTLSVerify    bool   `json:"insecure-skip-tls-verify,omitempty"`
	CertificateAuthorityData string `json:"certificate-authority-data,omitempty"`
	ProxyURL                 string `json:"proxy-url,omitempty"`
	DisableCompression       bool   `json:"disable-compression,omitempty"`
}

// execAnswer is the ExecCredential the plugin prints.
type execAnswer struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     *struct {
		Token                 string `json:"token"`
		ExpirationTimestamp   string `json:"expirationTimestamp"`
		ClientCertificateData string `json:"clientCertificateData"`
		ClientKeyData         string `json:"clientKeyData"`
	} `json:"status"`
}

func hasPathSep(cmd string) bool {
	return strings.ContainsRune(cmd, '/') || (runtime.GOOS == "windows" && strings.ContainsRune(cmd, '\\'))
}

// execCommand resolves the plugin command: absolute as is, a bare name on
// PATH, a relative path with a separator against the kubeconfig's
// directory, and only when neither that file nor its directory can be
// changed by other users.
func execCommand(cmd, origin, who string) (string, error) {
	if filepath.IsAbs(cmd) || !hasPathSep(cmd) {
		return cmd, nil
	}
	if origin == "" {
		return "", fmt.Errorf("the exec plugin command %q of %s is a relative path; give it as an absolute path", clean(cmd, 200), who)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{origin, filepath.Dir(origin)} {
			fi, err := os.Stat(p)
			if err != nil {
				return "", fmt.Errorf("the exec plugin command %q of %s is a relative path and %s cannot be checked, so it is not run; give the command as an absolute path", clean(cmd, 200), who, p)
			}
			if fi.Mode().Perm()&0o022 != 0 {
				return "", fmt.Errorf("the exec plugin command %q of %s is a relative path and %s is writable by other users, so it is not run; give the command as an absolute path or make %s writable only by you", clean(cmd, 200), who, p, p)
			}
		}
	}
	return filepath.Join(filepath.Dir(origin), cmd), nil
}

// execEnv is the process environment, then the plugin's env entries from
// the kubeconfig, then KUBERNETES_EXEC_INFO. Nothing else is added.
func execEnv(x *kubeExec, info []byte, who string) ([]string, error) {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, kubeExecInfoEnv+"=") {
			env = append(env, kv)
		}
	}
	for _, e := range x.Env {
		if e.Name == "" || strings.ContainsAny(e.Name, "=\x00") || strings.ContainsRune(e.Value, 0) {
			return nil, fmt.Errorf("the exec plugin of %s has an env entry with an empty or invalid name", who)
		}
		if e.Name == kubeExecInfoEnv {
			continue
		}
		env = append(env, e.Name+"="+e.Value)
	}
	return append(env, kubeExecInfoEnv+"="+string(info)), nil
}

// runKubeExec runs the exec credential plugin and returns its token and
// expiry. Errors never carry the plugin's stdout, its arguments or its
// env values; stderr is cut to one line with token-looking text blanked.
func runKubeExec(ctx context.Context, o KubeOptions, who string, x *kubeExec, origin string, cl *kubeCluster, clFrom string) (string, time.Time, error) {
	api := strings.TrimSpace(x.APIVersion)
	switch api {
	case kubeExecV1, kubeExecV1beta1:
	case "":
		return "", time.Time{}, fmt.Errorf("the exec plugin of %s has no apiVersion; set %s", who, kubeExecV1)
	default:
		return "", time.Time{}, fmt.Errorf("the exec plugin of %s uses apiVersion %q, which the launcher does not support; use %s or %s", who, clean(api, 80), kubeExecV1, kubeExecV1beta1)
	}
	if strings.TrimSpace(x.Command) == "" {
		return "", time.Time{}, fmt.Errorf("the exec plugin of %s has no command", who)
	}
	if strings.EqualFold(strings.TrimSpace(x.InteractiveMode), "Always") {
		return "", time.Time{}, fmt.Errorf("the exec plugin of %s needs a terminal (interactiveMode: Always), which the launcher does not give it; run a kubectl command once so the plugin keeps its sign-in, or set interactiveMode: IfAvailable", who)
	}
	cmd, err := execCommand(x.Command, origin, who)
	if err != nil {
		return "", time.Time{}, err
	}
	var info execInfo
	info.APIVersion, info.Kind = api, "ExecCredential"
	if x.ProvideClusterInfo && cl != nil {
		ec := &execCluster{
			Server: cl.Server, TLSServerName: cl.TLSServerName, InsecureSkipTLSVerify: cl.InsecureSkipTLSVerify,
			CertificateAuthorityData: strings.TrimSpace(cl.CertificateAuthorityData), ProxyURL: cl.ProxyURL, DisableCompression: cl.DisableCompression,
		}
		if ec.CertificateAuthorityData == "" && cl.CertificateAuthority != "" {
			p := relTo(cl.CertificateAuthority, clFrom)
			b, err := o.ReadFile(p)
			if err != nil {
				return "", time.Time{}, fmt.Errorf("the certificate-authority file %s of the cluster cannot be read: %s", p, readReason(err))
			}
			ec.CertificateAuthorityData = base64.StdEncoding.EncodeToString(b)
		}
		info.Spec.Cluster = ec
	}
	infoJSON, err := json.Marshal(&info)
	if err != nil {
		return "", time.Time{}, err
	}
	env, err := execEnv(x, infoJSON, who)
	if err != nil {
		return "", time.Time{}, err
	}
	plugin := fmt.Sprintf("the exec plugin %q of %s", clean(x.Command, 200), who)
	runCtx, cancel := context.WithTimeout(ctx, o.execTimeout)
	defer cancel()
	out, err := o.RunExec(runCtx, cmd, append([]string(nil), x.Args...), env, nil)
	if err != nil {
		switch {
		case ctx.Err() != nil:
			return "", time.Time{}, fmt.Errorf("%s was stopped: %w", plugin, ctx.Err())
		case errors.Is(runCtx.Err(), context.DeadlineExceeded):
			return "", time.Time{}, fmt.Errorf("%s did not answer within %s; run it once in a terminal (for example kubectl get namespaces) to finish any sign-in it asks for", plugin, o.execTimeout)
		case errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist):
			msg := plugin + " was not found"
			if h := strings.TrimSpace(x.InstallHint); h != "" {
				msg += "; " + stderrLine(h)
			}
			return "", time.Time{}, errors.New(msg)
		}
		msg := plugin + " failed"
		if line := stderrLine(err.Error()); line != "" {
			msg += ": " + line
		}
		return "", time.Time{}, errors.New(msg)
	}
	var a execAnswer
	if json.Unmarshal(bytes.TrimSpace(out), &a) != nil {
		return "", time.Time{}, fmt.Errorf("%s printed something that is not an ExecCredential JSON object", plugin)
	}
	if a.Kind != "" && a.Kind != "ExecCredential" {
		return "", time.Time{}, fmt.Errorf("%s printed a %q object, not an ExecCredential", plugin, clean(a.Kind, 40))
	}
	if a.APIVersion != "" && a.APIVersion != api {
		return "", time.Time{}, fmt.Errorf("%s answered with apiVersion %q, but the kubeconfig asks for %s", plugin, clean(a.APIVersion, 80), api)
	}
	if a.Status == nil {
		return "", time.Time{}, fmt.Errorf("%s printed an ExecCredential without a status", plugin)
	}
	if a.Status.Token == "" {
		if a.Status.ClientCertificateData != "" || a.Status.ClientKeyData != "" {
			return "", time.Time{}, fmt.Errorf("%s returned only a client certificate; %s", plugin, kubeCertRefusal)
		}
		return "", time.Time{}, fmt.Errorf("%s returned no token", plugin)
	}
	tok, ok := oneToken([]byte(a.Status.Token))
	if !ok {
		return "", time.Time{}, fmt.Errorf("%s returned a token that is not a single token", plugin)
	}
	var exp time.Time
	if ts := strings.TrimSpace(a.Status.ExpirationTimestamp); ts != "" {
		if exp, err = time.Parse(time.RFC3339, ts); err != nil {
			return "", time.Time{}, fmt.Errorf("%s returned an expirationTimestamp that is not an RFC 3339 time", plugin)
		}
		if !exp.After(o.Now()) {
			return "", time.Time{}, fmt.Errorf("%s returned a token that expired at %s; check this computer's clock", plugin, exp.UTC().Format(time.RFC3339))
		}
	}
	return tok, exp, nil
}

// tokenLikeRE matches text that may be a credential: a JWT start or a run
// of 20 or more base64url characters.
var tokenLikeRE = regexp.MustCompile(`eyJ[A-Za-z0-9_\-.=+/]*|[A-Za-z0-9_\-]{20,}`)

// stderrLine is the first non-empty line of s with token-looking text
// blanked, cut to 200 characters.
func stderrLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		return clean(tokenLikeRE.ReplaceAllString(line, "[hidden]"), 200)
	}
	return ""
}

// execFailure is a plugin run that failed; its text is the plugin's
// stderr when it wrote any.
type execFailure struct {
	err    error
	stderr string
}

func (e *execFailure) Error() string {
	if strings.TrimSpace(e.stderr) != "" {
		return e.stderr
	}
	return e.err.Error()
}

func (e *execFailure) Unwrap() error { return e.err }

// capBuffer keeps at most max bytes and notes when more were written.
type capBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (b *capBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room < len(p) {
		b.over = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func runExecDefault(ctx context.Context, name string, args []string, env []string, stdin []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, errb := &capBuffer{max: maxBody}, &capBuffer{max: kubeStderrMax}
	cmd.Stdout, cmd.Stderr = out, errb
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		return nil, &execFailure{err: err, stderr: errb.buf.String()}
	}
	if out.over {
		return nil, errors.New("the plugin printed more than 1 MiB")
	}
	return out.buf.Bytes(), nil
}
