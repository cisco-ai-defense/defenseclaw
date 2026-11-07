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

package harness

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// caVars are the CA variables OpenShell sets for the workload, which
// trustedCAScript points at OpenShell's bundle plus the trusted CAs.
var caVars = []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS", "DENO_CERT"}

// #1296, GAP-0065, GAP-0066, GAP-0074: OpenShell's sandbox bundle is made
// from its supervisor's own store, without the trusted CAs the image's
// system store holds. In an image with trusted CAs every launcher, login
// shell and `sandbox exec` command points each CA variable OpenShell set at
// a bundle of OpenShell's plus the trusted CAs, which verifies the proxy's
// certificates, OpenShell's own and the public ones; an image without
// trusted CAs keeps OpenShell's variables, and so does a sandbox where the
// bundle cannot be written.
func TestSandboxShellsGiveEveryRuntimeTheTrustedCAs(t *testing.T) {
	sh := binSh(t)
	binBash(t) // the wrapper runs under bash -p
	for _, name := range Names() {
		spec, _ := Get(name)
		if !strings.Contains(string(spec.Launcher().Data), trustedCAScript) {
			t.Errorf("the %s launcher does not run the trusted CA script", name)
		}
	}
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca-certificates", "defenseclaw")
	runPrefix := filepath.Join(dir, "run", "defenseclaw-ca")
	if err := os.MkdirAll(filepath.Dir(runPrefix), 0o755); err != nil {
		t.Fatal(err)
	}
	runDir := runPrefix + "-" + strconv.Itoa(os.Getuid())
	ours := filepath.Join(runDir, "ca-bundle.pem")

	// OpenShell's material: its CA alone and its bundle (the supervisor's
	// public roots plus its CA), side by side.
	material := filepath.Join(dir, "openshell-supervisor-ca", "material")
	if err := os.MkdirAll(material, 0o755); err != nil {
		t.Fatal(err)
	}
	public, supervisor, proxy := openshelltest.NewCA(t, "Public Root CA"), openshelltest.NewCA(t, "OpenShell Sandbox CA"),
		openshelltest.NewCA(t, "Corp Inspection Root CA")
	bundle, openShellCA := filepath.Join(material, "ca-bundle.crt"), filepath.Join(material, "ca.crt")
	writeTestFile(t, bundle, append(append([]byte(nil), public.PEM...), supervisor.PEM...), 0o444)
	writeTestFile(t, openShellCA, supervisor.PEM, 0o444)

	write := func(name string, data []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		// The in-image directories, moved into the test's own.
		s := strings.ReplaceAll(string(data), openshell.SandboxTrustedCADir, caDir)
		writeTestFile(t, p, []byte(strings.ReplaceAll(s, openshell.SandboxTrustedCARunDir, runPrefix)), mode)
		return p
	}
	profile := write("profile.sh", shellFile(t, Copilot, SandboxProfilePath).Data, 0o644)
	wrapper := write("sandbox-env", shellFile(t, Copilot, SandboxEnvPath).Data, 0o755)
	var record strings.Builder
	for _, v := range caVars {
		fmt.Fprintf(&record, "printf '%s=%%s\\n' \"${%s-<unset>}\"\n", v, v)
	}
	run := func(env []string) map[string]map[string]string {
		env = append([]string{"PATH=/usr/bin:/bin"}, env...)
		login := exec.Command(sh, "-c", ". "+profile+"\n"+record.String())
		login.Env = env
		wrapped := exec.Command(wrapper, sh, "-c", record.String())
		wrapped.Env = env
		out := map[string]map[string]string{}
		for what, cmd := range map[string]*exec.Cmd{"login shell": login, "sandbox exec": wrapped} {
			b, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v\n%s", what, err, b)
			}
			out[what] = shellEnvLines(string(b))
		}
		return out
	}
	openShellEnv := []string{"SSL_CERT_FILE=" + bundle, "REQUESTS_CA_BUNDLE=" + bundle, "CURL_CA_BUNDLE=" + bundle, "GIT_SSL_CAINFO=" + bundle,
		"NODE_EXTRA_CA_CERTS=" + openShellCA, "DENO_CERT=" + openShellCA}
	envOf := func(env []string) map[string]string {
		m := map[string]string{}
		for _, v := range caVars {
			m[v] = "<unset>"
		}
		for _, kv := range env {
			k, v, _ := strings.Cut(kv, "=")
			m[k] = v
		}
		return m
	}
	expect := func(what, step string, got, want map[string]string) {
		t.Helper()
		for _, v := range caVars {
			if got[v] != want[v] {
				t.Errorf("%s, %s: %s=%q, want %q", step, what, v, got[v], want[v])
			}
		}
	}

	// No trusted CAs in the image: OpenShell's variables stay.
	for what, got := range run(openShellEnv) {
		expect(what, "no trusted CAs", got, envOf(openShellEnv))
	}
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Fatalf("an image without trusted CAs wrote %s: %v", runDir, err)
	}

	if err := os.MkdirAll(caDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(caDir, "defenseclaw-trusted-ca-01.crt"), proxy.PEM, 0o644)
	all := func(path string) map[string]string {
		m := map[string]string{}
		for _, v := range caVars {
			m[v] = path
		}
		return m
	}
	for what, got := range run(openShellEnv) {
		expect(what, "trusted CAs", got, all(ours))
	}
	verifies := func(step string, cas ...openshelltest.CA) {
		t.Helper()
		data, err := os.ReadFile(ours)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			t.Fatalf("%s: %s holds no certificate", step, ours)
		}
		for _, ca := range cas {
			leaf := openshelltest.NewLeafCert(t, ca, "api.example.com")
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "api.example.com", Roots: pool}); err != nil {
				t.Errorf("%s: a certificate from %s does not verify with %s: %v", step, ca.Cert.Subject.CommonName, ours, err)
			}
		}
	}
	verifies("trusted CAs", public, supervisor, proxy)
	if fi, err := os.Stat(runDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("%s: %v %v, want an owner-only directory", runDir, fi, err)
	}
	if fi, err := os.Stat(ours); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s: %v %v, want an owner-only file", ours, fi, err)
	}
	if left, _ := filepath.Glob(filepath.Join(runDir, ".ca-bundle.*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}

	// A shell started from a launcher already has the bundle: unchanged.
	nested := []string{}
	for v, p := range all(ours) {
		nested = append(nested, v+"="+p)
	}
	for what, got := range run(nested) {
		expect(what, "nested shell", got, all(ours))
	}

	// GAP-0127: the first shell records OpenShell's bundle, so a
	// SSL_CERT_FILE the caller sets before a nested login shell
	// (env SSL_CERT_FILE=... sh -l) is the caller's and is kept; the other
	// variables keep the bundle.
	inner := write("inner.sh", []byte(". "+profile+"\n"+record.String()), 0o644)
	nestedLogin := write("nested.sh", []byte("SSL_CERT_FILE="+openshell.SandboxSystemCABundle+"; export SSL_CERT_FILE\n"+
		"printf 'base=%s\\n' \"${"+openshell.EnvTrustedCABase+"-<unset>}\"\nexec /bin/sh "+inner+"\n"), 0o644)
	nestedWant := all(ours)
	nestedWant["SSL_CERT_FILE"] = openshell.SandboxSystemCABundle
	for what, cmd := range map[string]*exec.Cmd{
		"login shell":  exec.Command(sh, "-c", ". "+profile+"\n. "+nestedLogin),
		"sandbox exec": exec.Command(wrapper, sh, nestedLogin),
	} {
		cmd.Env = append([]string{"PATH=/usr/bin:/bin"}, openShellEnv...)
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s, nested login shell: %v\n%s", what, err, b)
		}
		got := shellEnvLines(string(b))
		if got["base"] != bundle {
			t.Errorf("%s, nested login shell: %s=%q, want OpenShell's bundle %q", what, openshell.EnvTrustedCABase, got["base"], bundle)
		}
		expect(what, "nested login shell after the caller set SSL_CERT_FILE", got, nestedWant)
	}

	// A variable the caller pointed elsewhere is kept.
	custom := append(append([]string(nil), openShellEnv[:1]...), append([]string{"REQUESTS_CA_BUNDLE=/srv/certs/corp.pem"}, openShellEnv[2:]...)...)
	want := all(ours)
	want["REQUESTS_CA_BUNDLE"] = "/srv/certs/corp.pem"
	for what, got := range run(custom) {
		expect(what, "caller's variable", got, want)
	}

	// OpenShell's CA changes with a sandbox start: the bundle follows.
	next := openshelltest.NewCA(t, "OpenShell Sandbox CA 2")
	writeTestFile(t, bundle, append(append([]byte(nil), public.PEM...), next.PEM...), 0o444)
	run(openShellEnv)
	verifies("new OpenShell CA", next, proxy)

	// Without SSL_CERT_FILE the image's system bundle, which holds the
	// trusted CAs, fills the unset variables; a set one stays.
	want = all(openshell.SandboxSystemCABundle)
	want["NODE_EXTRA_CA_CERTS"] = "/srv/certs/node.pem"
	for what, got := range run([]string{"NODE_EXTRA_CA_CERTS=/srv/certs/node.pem"}) {
		expect(what, "no SSL_CERT_FILE", got, want)
	}

	// OpenShell's bundle missing, or the directory not the caller's own (a
	// symlink): OpenShell's variables stay, so an inspected connection fails
	// rather than verifying with less.
	gone := append([]string{"SSL_CERT_FILE=" + bundle + ".gone"}, openShellEnv[1:]...)
	for what, got := range run(gone) {
		expect(what, "missing bundle", got, envOf(gone))
	}
	if err := os.RemoveAll(runDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), runDir); err != nil {
		t.Fatal(err)
	}
	for what, got := range run(openShellEnv) {
		expect(what, "symlinked directory", got, envOf(openShellEnv))
	}
}

func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	_ = os.Chmod(path, 0o644)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
