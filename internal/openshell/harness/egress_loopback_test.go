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
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http/httpproxy"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// The create environment is shared by every connector and compute driver.
// Provider hosts still have their direct rule, and other destinations still
// use the configured proxy.
func TestSandboxLoopbackProxyExclusions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenShell sandbox artifacts are not rendered on Windows hosts")
	}
	const proxy = "http://proxy.example:18972"
	for _, name := range Names() {
		spec, _ := Get(name)
		profiles := spec.CredentialProfiles("us-east-1")
		ids := []string{""}
		for _, cp := range profiles {
			ids = append(ids, cp.ProfileID)
		}
		for _, id := range ids {
			t.Run(name+"/"+id, func(t *testing.T) {
				env, err := spec.Env(EnvOptions{
					Artifacts: artifactsFor(t, spec), CredentialProfile: id,
					BedrockRegion: "us-east-1", EgressProxyURL: proxy,
				})
				if err != nil {
					t.Fatal(err)
				}
				list := env["NO_PROXY"]
				if list != env["no_proxy"] || list != env[openshell.EnvEgressBypass] {
					t.Fatalf("proxy exclusions differ across environment names")
				}
				SetNoProxy(env, list)
				if env["NO_PROXY"] != list {
					t.Fatalf("setting proxy exclusions a second time changed %q to %q", list, env["NO_PROXY"])
				}
				seen := map[string]bool{}
				for _, host := range strings.Split(list, ",") {
					if seen[host] {
						t.Errorf("duplicate proxy exclusion %q", host)
					}
					seen[host] = true
				}
				for _, host := range []string{"127.0.0.0/8", "127.0.0.1", "::1", "localhost", connector.SandboxIngressHost} {
					if !seen[host] {
						t.Errorf("proxy exclusions lack %q: %q", host, list)
					}
				}
				if seen["outside.example"] {
					t.Errorf("ordinary external destination excluded from the proxy: %q", list)
				}
				selectProxy := (&httpproxy.Config{HTTPSProxy: proxy, NoProxy: list}).ProxyFunc()
				for _, host := range []string{"example.com", "internal.example.com"} {
					selected, err := selectProxy(&url.URL{Scheme: "https", Host: host})
					if err != nil || selected == nil || selected.String() != proxy {
						t.Errorf("%s proxy route = %v, %v", host, selected, err)
					}
				}
				if id != "" {
					cp, err := spec.CredentialProfile(id, "us-east-1")
					if err != nil {
						t.Fatal(err)
					}
					for _, host := range cp.Hosts {
						if !seen[host] {
							t.Errorf("credential host %q lost its direct route", host)
						}
						selected, err := selectProxy(&url.URL{Scheme: "https", Host: host})
						if err != nil || selected != nil {
							t.Errorf("credential host %q proxy route = %v, %v", host, selected, err)
						}
					}
				}
			})
		}
	}
}

func TestSandboxProxyDefaultKeepsLocalServicesDirect(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is required")
	}
	profile := filepath.Join(t.TempDir(), "sandbox-profile.sh")
	if err := os.WriteFile(profile, shellFile(t, OpenCode, SandboxProfilePath).Data, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", ". "+profile+"; printf '%s\\n' \"$NO_PROXY\" \"$no_proxy\"")
	cmd.Env = []string{openshell.EnvEgressURL + "=http://proxy.example:18972"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	for _, list := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		seen := map[string]bool{}
		for _, host := range strings.Split(list, ",") {
			seen[host] = true
		}
		for _, host := range []string{"127.0.0.0/8", "127.0.0.1", "::1", "localhost", connector.SandboxIngressHost} {
			if !seen[host] {
				t.Errorf("launcher default lacks %q: %q", host, list)
			}
		}
	}
}

// A local proxy uses the sandbox's own network namespace for loopback and
// preserves the existing egress proxy for ordinary outside requests. Node 22
// and Python do not apply the CIDR exclusion in NO_PROXY to every 127/8 host.
func TestSandboxProxyRoutesLoopbackInSandboxNamespace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sandbox proxy runs in Linux images")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node runtime is not installed on this test host")
	}
	script, err := os.ReadFile("local_proxy.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range Names() {
		spec, _ := Get(name)
		found := false
		for _, file := range spec.ShellFiles() {
			if file.Path != LauncherDir+"/local_proxy.py" {
				continue
			}
			found = true
			if file.Owner != connector.SandboxOwnerRoot || file.Mode != 0o644 || string(file.Data) != string(script) {
				t.Errorf("%s image does not carry the root-owned local proxy", name)
			}
		}
		if !found {
			t.Errorf("%s image lacks the local proxy", name)
		}
		if !strings.Contains(string(shellFile(t, spec, SandboxProfilePath).Data), "local_proxy.py --ensure") {
			t.Errorf("%s profile does not start the local proxy", name)
		}
	}
	file := filepath.Join(t.TempDir(), "local_proxy.py")
	if err := os.WriteFile(file, script, 0o644); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var upstreamHits []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamHits = append(upstreamHits, r.Method+" "+r.Host)
		mu.Unlock()
		if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		if r.Host == "denied.example" || strings.HasPrefix(r.Host, "denied.example:") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "DENIED")
			return
		}
		if r.Method != http.MethodConnect {
			_, _ = io.WriteString(w, "PROXIED")
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			t.Errorf("tunnel request: %v", err)
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nPROXIED")
	}))
	defer upstream.Close()
	upstreamURL := strings.Replace(upstream.URL, "://", "://user:pass@", 1)
	env, err := OpenCode.Env(EnvOptions{Artifacts: artifactsFor(t, OpenCode), EgressProxyURL: upstreamURL})
	if err != nil {
		t.Fatal(err)
	}

	// Source the generated profile with the installed Python asset, including
	// its startup and reuse path. A private state directory identifies the one
	// child this test starts for cleanup.
	stateRoot := t.TempDir()
	stateDir := filepath.Join(stateRoot, "defenseclaw-local-proxy-"+strconv.Itoa(os.Getuid()))
	t.Cleanup(func() {
		entries, _ := os.ReadDir(stateDir)
		for _, entry := range entries {
			if entry.Name() == ".lock" || entry.IsDir() {
				continue
			}
			state, err := os.ReadFile(filepath.Join(stateDir, entry.Name()))
			if err != nil {
				continue
			}
			pid, err := strconv.Atoi(strings.SplitN(string(state), "\n", 2)[0])
			if err == nil && pid > 0 {
				if process, err := os.FindProcess(pid); err == nil {
					_ = process.Kill()
					_ = process.Release()
				}
			}
		}
	})
	profile := filepath.Join(t.TempDir(), "sandbox-profile.sh")
	profileData := strings.ReplaceAll(string(shellFile(t, OpenCode, SandboxProfilePath).Data), LauncherDir+"/local_proxy.py", file)
	if err := os.WriteFile(profile, []byte(profileData), 0o644); err != nil {
		t.Fatal(err)
	}
	profileCmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", `. "$1"; printf '%s\n' "$HTTP_PROXY"`, "sh", profile)
	profileCmd.Env = []string{
		openshell.EnvEgressURL + "=" + upstreamURL,
		openshell.EnvEgressBypass + "=" + env["NO_PROXY"],
		"TMPDIR=" + stateRoot,
	}
	profileOut, err := profileCmd.CombinedOutput()
	localProxy := strings.TrimSpace(string(profileOut))
	if err != nil || !strings.HasPrefix(localProxy, "http://127.0.0.1:") {
		t.Fatalf("sandbox profile proxy = %q, %v", profileOut, err)
	}

	run := func(name, binary, program, address, want string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), binary, "-e", program, address)
			if binary == python {
				cmd.Args = []string{python, "-c", program, address}
			}
			cmd.Env = []string{
				"PATH=" + os.Getenv("PATH"), "NODE_USE_ENV_PROXY=1", "NODE_NO_WARNINGS=1",
				"HTTP_PROXY=" + localProxy, "HTTPS_PROXY=" + localProxy,
				"http_proxy=" + localProxy, "https_proxy=" + localProxy,
				"NO_PROXY=" + env["NO_PROXY"], "no_proxy=" + env["NO_PROXY"],
			}
			out, err := cmd.CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != want {
				t.Fatalf("%s route: %v, %q; want %q", address, err, out, want)
			}
		})
	}
	nodeCode := `fetch(process.argv[1]).then(r=>r.text()).then(console.log).catch(e=>{console.error(e);process.exit(1)})`
	pythonCode := `import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1],timeout=5).read().decode())`
	var localTunnelTarget string
	for _, route := range []struct{ host, listen string }{
		{"127.0.0.2", "127.0.0.2"}, {"127.1.2.3", "127.1.2.3"},
		{"127.1", "127.0.0.1"}, {"::1", "::1"},
	} {
		listener, err := net.Listen("tcp", net.JoinHostPort(route.listen, "0"))
		if err != nil {
			if route.host == "::1" {
				t.Logf("IPv6 loopback unavailable: %v", err)
				continue
			}
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "DIRECT") }))
		server.Listener = listener
		server.Start()
		defer server.Close()
		if route.host == "127.0.0.2" {
			localTunnelTarget = listener.Addr().String()
		}
		// The listener address already includes the proper IPv6 brackets.
		address := "http://" + net.JoinHostPort(route.host, strings.TrimPrefix(listener.Addr().String(), net.JoinHostPort(route.listen, ""))) + "/"
		run("node/"+route.host, node, nodeCode, address, "DIRECT")
		run("python/"+route.host, python, pythonCode, address, "DIRECT")
	}
	hostsFile, err := os.ReadFile("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"ip6-localhost", "ip6-loopback", "localhost.localdomain"} {
		listed := false
		for _, line := range strings.Split(string(hostsFile), "\n") {
			fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(fields) > 1 {
				for _, name := range fields[1:] {
					listed = listed || name == alias
				}
			}
		}
		if !listed && alias != "localhost.localdomain" {
			continue
		}
		ips, err := net.LookupIP(alias)
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range ips {
			if !ip.IsLoopback() {
				continue
			}
			listener, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "DIRECT") }))
			server.Listener = listener
			server.Start()
			defer server.Close()
			address := "http://" + net.JoinHostPort(alias, strings.TrimPrefix(listener.Addr().String(), net.JoinHostPort(ip.String(), ""))) + "/"
			run("node/"+alias, node, nodeCode, address, "DIRECT")
			run("python/"+alias, python, pythonCode, address, "DIRECT")
			break
		}
	}
	if _, err := net.LookupIP("localhost."); err == nil {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "DIRECT") }))
		server.Listener = listener
		server.Start()
		defer server.Close()
		address := "http://localhost.:" + strings.TrimPrefix(listener.Addr().String(), "127.0.0.1:") + "/"
		run("node/localhost-dot", node, nodeCode, address, "DIRECT")
		run("python/localhost-dot", python, pythonCode, address, "DIRECT")
	}
	run("node/external", node, nodeCode, "http://outside.example/test", "PROXIED")
	run("python/external", python, pythonCode, "http://outside.example/test", "PROXIED")
	run("node/denied", node, `fetch(process.argv[1]).then(r=>console.log(r.status)).catch(e=>{let text=[e.message,e.cause?.message,e.cause?.cause?.message].join(' ');if(text.includes('403')) console.log('403'); else {console.error(e);process.exit(1)}})`, "http://denied.example/test", "403")
	run("python/denied", python, `import sys,urllib.request,urllib.error
try: urllib.request.urlopen(sys.argv[1],timeout=5)
except urllib.error.HTTPError as error: print(error.code)`, "http://denied.example/test", "403")
	tunnel := func(target, want string) {
		t.Helper()
		conn, err := net.Dial("tcp", strings.TrimPrefix(localProxy, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		request := "GET / HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"
		if _, err := io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"+request); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "HTTP/1.1 200 ") {
			t.Fatalf("CONNECT %s: %q, %v", target, line, err)
		}
		for {
			line, err = reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if line == "\r\n" {
				break
			}
		}
		response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || string(body) != want {
			t.Fatalf("CONNECT %s body = %q, %v; want %q", target, body, err, want)
		}
	}
	tunnel(localTunnelTarget, "DIRECT")
	tunnel("outside.example:443", "PROXIED")
	mu.Lock()
	defer mu.Unlock()
	if len(upstreamHits) != 5 {
		t.Fatalf("upstream routes = %v; want five outside requests", upstreamHits)
	}
	for _, hit := range upstreamHits {
		if !strings.Contains(hit, "outside.example") && !strings.Contains(hit, "denied.example") {
			t.Errorf("local destination reached upstream: %s", hit)
		}
	}
}
