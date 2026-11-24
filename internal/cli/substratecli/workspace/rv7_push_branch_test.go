//go:build !windows

package workspace

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0843: the image-bound helper and trust bundle must reach the actual
// HTTPS discovery and push, while post-review actor config stays untrusted.
func TestRV7AuthenticatedHTTPSPushUsesImageCredentials(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	tmp := t.TempDir()
	origin := filepath.Join(tmp, "origin.git")
	gitT(t, tmp, "init", "-q", "--bare", origin)
	gitT(t, tmp, "--git-dir", origin, "config", "http.receivepack", "true")
	root := filepath.Join(tmp, "work")
	repo := filepath.Join(root, "app")
	gitT(t, tmp, "clone", "-q", origin, repo)
	if err := os.WriteFile(filepath.Join(repo, "README"), []byte("approved\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitT(t, repo, "add", ".")
	gitT(t, repo, "commit", "-qm", "approved")
	gitT(t, repo, "push", "-q", "origin", "HEAD:refs/heads/main")

	var authorized atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "fixture" || pass != "fixture-token" {
			w.Header().Set("WWW-Authenticate", "Basic realm=git")
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		authorized.Add(1)
		cmd := exec.Command("git", "http-backend")
		cmd.Env = append(os.Environ(),
			"GIT_PROJECT_ROOT="+tmp, "GIT_HTTP_EXPORT_ALL=1",
			"PATH_INFO="+r.URL.Path, "QUERY_STRING="+r.URL.RawQuery,
			"REQUEST_METHOD="+r.Method, "CONTENT_TYPE="+r.Header.Get("Content-Type"),
			"CONTENT_LENGTH="+strconv.FormatInt(r.ContentLength, 10),
			"REMOTE_USER=fixture", "REMOTE_ADDR=127.0.0.1",
			"SERVER_PROTOCOL=HTTP/1.1", "SERVER_NAME=localhost", "SERVER_PORT=443")
		cmd.Stdin = r.Body
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Errorf("git http-backend: %v: %s", err, stderr.String())
			http.Error(w, "backend failed", http.StatusInternalServerError)
			return
		}
		out := stdout.Bytes()
		split := bytes.Index(out, []byte("\r\n\r\n"))
		sep := 4
		if split < 0 {
			split = bytes.Index(out, []byte("\n\n"))
			sep = 2
		}
		if split < 0 {
			t.Errorf("git http-backend had no header separator: %q", out)
			http.Error(w, "backend response failed", http.StatusInternalServerError)
			return
		}
		status := http.StatusOK
		for _, line := range strings.Split(strings.ReplaceAll(string(out[:split]), "\r", ""), "\n") {
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			if strings.EqualFold(key, "Status") {
				fields := strings.Fields(value)
				if len(fields) > 0 {
					status, _ = strconv.Atoi(fields[0])
				}
			} else {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write(out[split+sep:])
	}))
	defer server.Close()

	ca := filepath.Join(tmp, "test-ca.pem")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(ca, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(tmp, "trusted-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\ncase \"$1\" in get) printf 'username=fixture\\npassword=fixture-token\\n' ;; esac\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	gitT(t, repo, "remote", "set-url", "origin", server.URL+"/origin.git")
	runner := func(ctx context.Context, argv []string, dir string, env map[string]string, timeout time.Duration) (string, string, int, error) {
		if len(argv) > 2 && argv[0] == "sh" && argv[1] == "-c" && strings.HasPrefix(argv[2], pushGit) {
			if !strings.Contains(argv[2], kit.CredHelper) || !strings.Contains(argv[2], kit.TrustBundle) {
				return "", "", 0, fmt.Errorf("review/push script omitted image-bound credential helper or CA")
			}
			argv = append([]string(nil), argv...)
			argv[2] = strings.ReplaceAll(strings.ReplaceAll(argv[2], kit.CredHelper, helper), kit.TrustBundle, ca)
		}
		return localExec(ctx, argv, dir, env, timeout)
	}
	p, err := PrepareBranchPush(context.Background(), runner, root, "a1", server.URL+"/origin.git", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Discard(context.Background(), runner)

	// Both files are actor-writable after review. A read of either would
	// select a failing helper or a nonexistent CA instead of the image pair.
	poisonHelper := filepath.Join(tmp, "poison-helper")
	if err := os.WriteFile(poisonHelper, []byte("#!/bin/sh\nexit 97\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	poison := "[credential]\n\thelper = " + poisonHelper + "\n[http]\n\tsslCAInfo = " + filepath.Join(tmp, "wrong-ca.pem") + "\n"
	if err := os.WriteFile(filepath.Join(p.snapshot, "g", "config"), []byte(poison), 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(tmp, "actor-home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(poison), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("GIT_SSL_CAINFO", filepath.Join(tmp, "wrong-ca.pem"))
	if err := p.Push(context.Background(), runner, "agent/approved", "a1", ""); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(rv4Ref(origin, "refs/heads/agent/approved")); got != p.Commit {
		t.Fatalf("origin branch = %q, want reviewed %s", got, p.Commit)
	}
	if authorized.Load() < 2 {
		t.Fatalf("authenticated HTTPS exchanges = %d, want review and push", authorized.Load())
	}
}
