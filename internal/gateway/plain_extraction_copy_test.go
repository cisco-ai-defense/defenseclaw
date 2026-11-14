// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// r107WriteTar writes a tar archive of headers (a body "x\n" for each
// regular file), gzip compressed when zipped.
func r107WriteTar(t *testing.T, path string, zipped bool, headers ...tar.Header) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var out io.Writer = file
	var zw *gzip.Writer
	if zipped {
		zw = gzip.NewWriter(file)
		out = zw
	}
	tw := tar.NewWriter(out)
	for _, header := range headers {
		header := header
		if header.Typeflag == tar.TypeReg {
			header.Size = 2
		}
		header.Mode = 0o600
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte("x\n")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestR107CopyOfAPlainExtractionIsPlain: a tar archive the hook client
// reads holds only regular files, so extracting it makes no link and a
// copy of the extracted folder (cp -a, rsync -a), or the folder itself,
// is written as plain files per user (rel-1-0-6:GAP-0339). A managed
// gateway that cannot read the archive behind ProtectHome keeps the opaque
// reading: the client's plain fact alone does not clear it (review 8).
// An archive with a symbolic link, a hard link or a .. name, an archive
// the command rewrites first, and a destination folder that already holds
// a keys link keep blocking.
func TestR107CopyOfAPlainExtractionIsPlain(t *testing.T) {
	setup := func(t *testing.T, f b36ManagedHookFixture) {
		reg := func(name string) tar.Header { return tar.Header{Name: name, Typeflag: tar.TypeReg} }
		r107WriteTar(t, filepath.Join(f.project, "plain.tar"), false, tar.Header{Name: "sub/", Typeflag: tar.TypeDir}, reg("p"), reg("sub/q"))
		r107WriteTar(t, filepath.Join(f.project, "plain.tgz"), true, reg("p"))
		r107WriteTar(t, filepath.Join(f.project, "link.tar"), false, tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys"})
		r107WriteTar(t, filepath.Join(f.project, "hard.tar"), false, tar.Header{Name: "p", Typeflag: tar.TypeLink, Linkname: "../.ssh/authorized_keys"})
		r107WriteTar(t, filepath.Join(f.project, "dotdot.tar"), false, reg("../p"))
		r107WriteTar(t, filepath.Join(f.project, "fifo.tar"), false, tar.Header{Name: "p", Typeflag: tar.TypeFifo})
		r107WriteTar(t, filepath.Join(f.project, "absolute.tar"), false, reg("/p"))
		r107WriteTar(t, filepath.Join(f.project, "backslash.tar"), false, reg(`..\p`))
		if err := os.Link(filepath.Join(f.project, "plain.tar"), filepath.Join(f.project, "alias.tar")); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"d0", "d1"} {
			if err := os.MkdirAll(filepath.Join(f.project, name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(f.keys, filepath.Join(f.project, "d0", "p")); err != nil {
			t.Fatal(err)
		}
	}
	r106Reader2CheckWith(t, []r106Reader2Row{
		{"plain tar, cp -a of the folder only", "project", `tar -xf plain.tar -C d1 && cp -a d1 e3`, "allow"},
		{"plain tar, cp -a of the folder, append to the copy", "project", `tar -xf plain.tar -C d1 && cp -a d1 e3 && echo k >> e3/p`, "allow/alert"},
		{"plain tar, rsync -a of the folder, append to the copy", "project", `tar -xf plain.tar -C d1 && rsync -a d1/ e2/ && echo k >> e2/p`, "allow/alert"},
		{"plain tar, append into the folder", "project", `tar -xf plain.tar -C d1 && echo k >> d1/sub/q`, "allow/alert"},
		{"plain tgz, cp -a of the folder, append to the copy", "project", `tar -xzf plain.tgz -C d1 && cp -a d1 e3 && echo k >> e3/p`, "allow/alert"},
		{"symlink tar, cp -a, append to the copy", "project", `tar -xf link.tar -C d1 && cp -a d1 e3 && echo k >> e3/p`, "alert/block"},
		{"symlink tar, append into the folder", "project", `tar -xf link.tar -C d1 && echo k >> d1/p`, "alert/block"},
		{"hard link tar, cp -a, append to the copy", "project", `tar -xf hard.tar -C d1 && cp -a d1 e3 && echo k >> e3/p`, "alert/block"},
		{"dot-dot tar, append", "project", `tar -xf dotdot.tar -C d1 && echo k >> d1/p`, "alert/block"},
		{"fifo member is not a plain file", "project", `tar -xf fifo.tar -C d1 && echo k >> d1/p`, "alert/block"},
		{"absolute member name is not plain", "project", `tar -xf absolute.tar -C d1 && echo k >> d1/p`, "alert/block"},
		{"backslash member name is not plain", "project", `tar -xf backslash.tar -C d1 && echo k >> d1/p`, "alert/block"},
		{"archive rewritten first", "project", `cp link.tar plain.tar; tar -xf plain.tar -C d1 && cp -a d1 e3 && echo k >> e3/p`, "alert/block"},
		{"archive rewritten first through a glob", "project", `cp link.tar p[l]ain.tar; tar -xf plain.tar -C d1 && echo k >> d1/p`, "alert/block"},
		{"archive rewritten first through a hard-linked name", "project", `cp link.tar alias.tar; tar -xf plain.tar -C d1 && echo k >> d1/p`, "alert/block"},
		{"two archive words", "project", `tar -xf plain.tar --file=plain.tgz -C d1 && echo k >> d1/p`, "alert/block"},
		{"plain tar into a folder holding a keys link, append through it", "project", `tar -xf plain.tar -C d0 && echo k >> d0/p`, "block"},
		{"plain tar into a folder holding a keys link, cp -a, append to the copy", "project", `tar -xf plain.tar -C d0 && cp -a d0 e4 && echo k >> e4/p`, "block"},
		{"plain tar after a link is made in the destination", "project", `mkdir -p d1 && ln -s ../../.ssh d1/ssh && tar -xf plain.tar -C d1 && echo k >> d1/ssh/authorized_keys`, "block"},
		{"write into the extraction scope (fake archive)", "project", `tar -C unpack -xf keys.tar; echo k >> unpack/n1.txt`, "alert/block"},
	}, setup)
}

// Per-user shell hooks post the agent's payload without a resolved-writes
// header. The installed hooks use this route for both Claude Code and Codex.
func TestR107PlainArchiveRewriteViaShellHook(t *testing.T) {
	rows := []struct {
		name, command, want string
	}{
		{"plain extraction", `tar -xf plain.tar -C d1 && echo k >> d1/p`, "allow/alert"},
		{"archive rewritten first", `cp link.tar plain.tar; tar -xf plain.tar -C d1 && cp -a d1 e3 && echo k >> e3/p`, "alert/block"},
		{"archive rewritten through hard link", `cp link.tar alias.tar; tar -xf plain.tar -C d1 && echo k >> d1/p`, "alert/block"},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, row := range rows {
			t.Run(connector+"/"+row.name, func(t *testing.T) {
				f := newB36ManagedHookFixture(t)
				r107WriteTar(t, filepath.Join(f.project, "plain.tar"), false,
					tar.Header{Name: "p", Typeflag: tar.TypeReg})
				r107WriteTar(t, filepath.Join(f.project, "link.tar"), false,
					tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys"})
				if err := os.Link(filepath.Join(f.project, "plain.tar"), filepath.Join(f.project, "alias.tar")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(f.project, "d1"), 0o700); err != nil {
					t.Fatal(err)
				}
				payload := mustJSON(t, map[string]any{
					"session_id": "r107-cpa480", "hook_event_name": "PreToolUse",
					"tool_name": "Bash", "tool_use_id": "toolu_r107_cpa480",
					"cwd": f.project, "permission_mode": "default",
					"transcript_path": "/tmp/none.jsonl",
					"tool_input":      map[string]any{"command": row.command},
				})
				wantPerUser, wantManaged, split := strings.Cut(row.want, "/")
				if !split {
					wantManaged = wantPerUser
				}
				if got := r106PerUserVerdict(t, connector, payload, ""); got != wantPerUser {
					t.Errorf("per-user shell %s: got %s, want %s", row.name, got, row.want)
				}
				header := f.clientHeader(t, payload)
				if got := f.post(t, connector, payload, header); got != wantManaged {
					t.Errorf("managed native %s: got %s, want %s", row.name, got, row.want)
				}
			})
		}
	}
}

// The archive reader's byte and member limits keep these extractions opaque.
func TestR107Review8TarPlainBounds(t *testing.T) {
	r106Reader2CheckWith(t, []r106Reader2Row{
		{"archive file exceeds 64 MiB", "project", `tar -xf overbytes.tar -C d1 && echo k >> d1/p`, "alert/block"},
	}, func(t *testing.T, f b36ManagedHookFixture) {
		if err := os.Mkdir(filepath.Join(f.project, "d1"), 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(f.project, "overbytes.tar")
		r107WriteTar(t, path, false, tar.Header{Name: "p", Typeflag: tar.TypeReg})
		if err := os.Truncate(path, (64<<20)+1); err != nil {
			t.Fatal(err)
		}
	})
	r106Reader2CheckWith(t, []r106Reader2Row{
		{"archive has 4097 members", "project", `tar -xf overmembers.tar -C d1 && echo k >> d1/p`, "alert/block"},
	}, func(t *testing.T, f b36ManagedHookFixture) {
		if err := os.Mkdir(filepath.Join(f.project, "d1"), 0o700); err != nil {
			t.Fatal(err)
		}
		headers := make([]tar.Header, 4097)
		for i := range headers {
			headers[i] = tar.Header{Name: "f" + strconv.Itoa(i), Typeflag: tar.TypeReg}
		}
		headers[len(headers)-1].Name = "p"
		r107WriteTar(t, filepath.Join(f.project, "overmembers.tar"), false, headers...)
	})
}

// A client fact must not turn an archive known to contain a link into a
// plain extraction on a managed gateway that cannot search the user's home.
func TestR107Review8ForgedTarPlainFact(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.Mkdir(filepath.Join(f.project, "d1"), 0o700); err != nil {
		t.Fatal(err)
	}
	r107WriteTar(t, filepath.Join(f.project, "link.tar"), false,
		tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys"})
	payload := f.payload(t, `tar -xf link.tar -C d1 && echo k >> d1/p`)
	realHeader := f.clientHeader(t, payload)
	targets, ok := hookpaths.Decode(realHeader)
	if !ok {
		t.Fatal("client header did not decode")
	}
	targets[hookpaths.TarPlainFactPrefix+filepath.Join(f.project, "link.tar")] = "1"
	header := encodeTargets(t, targets)
	for _, connector := range []string{"claudecode", "codex"} {
		if got := f.post(t, connector, payload, realHeader); got != "block" {
			t.Errorf("managed %s real client fact: %s, want block", connector, got)
		}
		if got := f.post(t, connector, payload, header); got != "block" {
			t.Errorf("managed %s forged plain fact: %s, want block", connector, got)
		}
	}
}

// A redirection command substitution can rewrite the archive through a hard
// link before tar opens it.
func TestR107Review9RedirectSubstitutionRewritesArchive(t *testing.T) {
	r106Reader2CheckWith(t, []r106Reader2Row{
		{"redirect substitution rewrites hard-linked archive", "project",
			`tar -xf plain.tar -C d1 > "$(cp link.tar alias.tar; echo out)" && echo k >> d1/p`, "alert/block"},
	}, func(t *testing.T, f b36ManagedHookFixture) {
		r107WriteTar(t, filepath.Join(f.project, "plain.tar"), false,
			tar.Header{Name: "p", Typeflag: tar.TypeReg})
		r107WriteTar(t, filepath.Join(f.project, "link.tar"), false,
			tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys"})
		if err := os.Link(filepath.Join(f.project, "plain.tar"), filepath.Join(f.project, "alias.tar")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(f.project, "d1"), 0o700); err != nil {
			t.Fatal(err)
		}
	})
}

// A redirected extraction keeps the ordinary command verdict even when its
// archive contains only regular files. A managed gateway that can read the
// project gives the same answer as a per-user gateway.
func TestR107Review9RedirectedPlainExtraction(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	r107WriteTar(t, filepath.Join(f.project, "plain.tar"), false,
		tar.Header{Name: "p", Typeflag: tar.TypeReg})
	if err := os.Mkdir(filepath.Join(f.project, "d1"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ name, command string }{
		{"stdout to project log", `tar -xf plain.tar -C d1 > extract.log`},
		{"stderr to project log", `tar -xf plain.tar -C d1 2> extract.log`},
		{"stdout to dev null", `tar -xf plain.tar -C d1 > /dev/null`},
		{"stderr to dev null", `tar -xf plain.tar -C d1 2> /dev/null`},
	} {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, connector := range []string{"claudecode", "codex"} {
			for _, managed := range []bool{false, true} {
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = connector
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
				req.Header.Set(hookpaths.Header, header)
				if connector == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				if managed {
					req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
				}
				recorder := httptest.NewRecorder()
				api.handleAgentHook(connector).ServeHTTP(recorder, req)
				if got := recorder.Body.String(); !strings.HasPrefix(got, `{"action":"allow"`) {
					t.Errorf("%s managed=%v %s: %s, want allow", connector, managed, row.name, got)
				}
			}
		}
	}
}
