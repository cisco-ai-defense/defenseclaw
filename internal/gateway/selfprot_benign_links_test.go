// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// selfProtRow is one shell command of the benign link and copy forms and
// the verdict an action-mode gateway must give it.
type selfProtRow struct{ id, cmd, want string }

// selfProtVerdict posts cmd to an action-mode gateway for connector, behind
// ProtectHome (managed, with the real hook client header) or per-user. The
// project holds build/out, src, ordinary and keylink (a link to the keys
// decoy); a link named dclink to the DefenseClaw state is added for BL rows.
func selfProtVerdict(t *testing.T, r selfProtRow, managed bool, connector string) string {
	t.Helper()
	f := newB36ManagedHookFixture(t)
	for _, dir := range []string{"build/out", "src", "ordinary", "../.defenseclaw"} {
		if err := os.MkdirAll(filepath.Join(f.project, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"a.txt", "b.txt", "README.md", "SOUL.md", "src/a.txt", "src/main.go", "build/x.o", "ordinary/o.txt", "../.defenseclaw/config.yaml"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if strings.HasPrefix(r.id, "BL") {
		if err := os.Symlink("../.defenseclaw", filepath.Join(f.project, "dclink")); err != nil {
			t.Fatal(err)
		}
	}
	payload := f.payload(t, r.cmd)
	header := f.clientHeader(t, payload)
	if managed {
		return f.post(t, connector, payload, header)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	switch body := recorder.Body.String(); {
	case strings.HasPrefix(body, `{"action":"block"`):
		return "block"
	case strings.HasPrefix(body, `{"action":"allow"`):
		return "allow"
	default:
		return "status " + recorder.Result().Status
	}
}

func checkSelfProtRows(t *testing.T, rows []selfProtRow, connectors ...string) {
	t.Helper()
	for _, managed := range []bool{true, false} {
		for _, connector := range connectors {
			for _, r := range rows {
				if got := selfProtVerdict(t, r, managed, connector); got != r.want {
					t.Errorf("%s managed=%v %s: %q = %s, want %s", r.id, managed, connector, r.cmd, got, r.want)
				}
			}
		}
	}
}

// A plain cp writes its own destination: that write skips only its own
// copy scope, also when the cp runs in a literal sh -c body (GAP-2582).
func TestSelfProtCopyOwnDestinationIsOrdinary(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"B01", `ln -s build/out bin && cp -a build/x.o dist.o`, "allow"},
		{"B07", `ln -s build/out bin && cp -a src dist && cp -a dist dist2`, "allow"},
		{"N03", `sh -c "ln -s build/out bin && cp -a build dist"`, "allow"},
		{"T10", `ln -s ../.ssh/authorized_keys k; cp -a k dist; echo key >> dist`, "block"},
		{"T13", `ln -s ../.ssh k; cp -a build dist; cp -a src/a.txt k/authorized_keys`, "block"},
		{"T02", `sh -c "ln -s ../.ssh k && cp -a src/a.txt k/authorized_keys"`, "block"},
	}, "claudecode", "codex")
}

// Behind ProtectHome, links unknown only inside copy scopes that cannot
// reach an operand are answered by the hook client walk (GAP-2582, GAP-2579).
func TestSelfProtManagedAliasOutsideCopyScope(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"N03p", `ln -s build/out bin && cp -a build dist`, "allow"},
		{"B03", `ln -sf ../src/a.txt link.txt && cp -a src out`, "allow"},
		{"B34", `nohup cp -r src src-bak && ln -s src-bak/main.go x.go`, "allow"},
		{"T18", `ln -s build/out bin && cp -a build dist && echo key >> keylink`, "block"},
		{"T21", `ln -s ~/.ssh build/k && cp -a build dist && echo key >> dist/k/authorized_keys`, "block"},
	}, "claudecode", "codex")
}

// env -C DIR ln runs ln in DIR, as a copy child does (GAP-2579, GAP-2576).
func TestSelfProtEnvChdirLinkIsPlaced(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"B21", `env -C ~/project ln -s build/out bin`, "allow"},
		{"L08", `env -C ~/project ln -sf ordinary/o.txt ln2.go; cp a.txt ln2.go`, "allow"},
		{"E02", `env -C ~/project ln -sf ../.ssh/authorized_keys ln3; cp a.txt ln3`, "block"},
		{"E03", `env -C ~/project ln -s ../.ssh ks; cp a.txt ks/authorized_keys`, "block"},
		{"A09", `env -C ~ ln -s .ssh/authorized_keys project/k7`, "block"},
	}, "claudecode", "codex")
}

// A static mv or find -exec mv after a static top-level cd is followed where
// it runs; a moved disk link to state keeps the links unknown (GAP-2602,
// GAP-2533).
func TestSelfProtMoveAfterStaticCdIsFollowed(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"C01", `cd ~/project && ln -s README.md docs.md; mv a.txt e.txt; ls`, "allow"},
		{"V2", `cd ~/project && ln -s src/main.go alias6.go; find . -type f -name "*.tmp" -exec mv {} build/ \;`, "allow"},
		{"C04", `cd ~/project && ln -s ../.ssh ks; mv a.txt e.txt; cp b.txt ks/authorized_keys`, "block"},
		{"C05", `cd ~/project && ln -s ../.ssh/authorized_keys k; mv k k2; echo x >> k2`, "block"},
		{"C06", `cd ~/project && ln -s README.md docs.md; mv keylink k2; echo x >> k2`, "block"},
	}, "claudecode", "codex")
}

// The own destination of a copy after a placed directory change is read
// against its own scope (GAP-2579).
func TestSelfProtCopyAfterDirectoryChange(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"B11", `env -C ~ cp -r project project-bak`, "allow"},
		{"E01", `env -C ~ cp -r project project-bak; echo key >> ~/project-bak/keylink`, "block"},
		{"E05", `env -C ~ cp -a project/keylink kl2; echo key >> ~/kl2`, "block"},
	}, "claudecode", "codex")
}

// git -c with an identity or display setting runs nothing, so the message
// stays text in a pwsh -Command body (GAP-1473); any other setting does not.
// The per-user gateway reads the quoted ~ of the body itself.
func TestSelfProtGitInertConfigIsText(t *testing.T) {
	for _, r := range []selfProtRow{
		{"P03", "pwsh -NoProfile -Command \"git -c user.name=vd commit --allow-empty -m \x27Document ~/.ssh/authorized_keys\x27\"", "allow"},
		{"P04", "pwsh -NoProfile -Command \"git -c user.name=vd -c user.email=vd@example.test commit --allow-empty -m \x27Document ~/.ssh/authorized_keys\x27\"", "allow"},
		{"PT2", "pwsh -NoProfile -Command \"git -c core.pager=x commit --allow-empty -m \x27Document ~/.ssh/authorized_keys\x27\"", "block"},
	} {
		if got := selfProtVerdict(t, r, false, "claudecode"); got != r.want {
			t.Errorf("%s per-user: %q = %s, want %s", r.id, r.cmd, got, r.want)
		}
	}
}

// cmd /c "mklink ..." makes the link ln makes, so a hard link of an
// ordinary file and a write through it are ordinary (GAP-2229, GAP-1266)
// and a link to the keys stays a key write.
func TestSelfProtCmdMklinkIsALink(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"H03", `cmd //c "mklink /H alias.md SOUL.md" ; printf y >> alias.md`, "allow"},
		{"HT3", `cmd //c "mklink /H hk ../.ssh/authorized_keys" ; printf y >> hk`, "block"},
		{"HT4", `cmd //c "mklink /D d ..\.ssh" ; printf y >> d/authorized_keys`, "block"},
		{"HT5", `cmd //c "mklink /H hk ../.ssh/authorized_keys & echo" ; printf y >> hk`, "block"},
	}, "claudecode", "codex")
}

// A directory change that only a literal shell body makes is read by the
// body own statement walk: a link made after it is placed in the directory
// it names, as the plain list is (GAP-2602). A link made outside the body, a
// dynamic directory and every write through a link to state keep blocking.
func TestSelfProtShellBodyDirectoryChange(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"W01", `bash -lc 'cd ~/project && ln -s README.md docs.md; mv a.txt e.txt; ls'`, "allow"},
		{"W02", `bash -c 'cd ~/project && ln -s README.md docs.md; mv a.txt e.txt; ls'`, "allow"},
		{"W04", `bash -lc 'cd ~/project && ln -s README.md docs.md; ls'`, "allow"},
		{"W05", `bash -lc 'cd ~/project && mv a.txt e.txt'`, "allow"},
		{"Y02", `bash -c 'cd src && ln -s ../a.txt b'`, "allow"},
		{"Y03", `bash -c 'cd ~/project/src && ln -s ../a.txt b'`, "allow"},
		{"Y06", `bash -c 'cd build && ln -s out bin'`, "allow"},
		{"W07", `bash -lc 'cd ~/project && ln -s ../.ssh ks; mv a.txt e.txt; cp b.txt ks/authorized_keys'`, "block"},
		{"W08", `bash -lc 'ln -s ../.ssh/authorized_keys k; echo x >> k'`, "block"},
		{"W09", `bash -c 'cd ~/project && ln -s README.md docs.md; mv keylink k2; echo x >> k2'`, "block"},
		{"X01", `bash -c 'cd src && ln -s ../../.ssh k && cp ../a.txt k/authorized_keys'`, "block"},
		{"X02", `ln -s ../.ssh k; bash -lc 'cd src && echo x >> ../k/authorized_keys'`, "block"},
		{"X03", `bash -c 'cd src && ln -s ../../.ssh/authorized_keys k; echo x >> k'`, "block"},
		{"X05", `bash -c 'cd ~ && ln -s .ssh/authorized_keys project/k7'`, "block"},
		{"X07", `bash -c 'cd ~/project && ln -s ../.ssh ks'; echo x >> ks/authorized_keys`, "block"},
		{"X08", `cd src && bash -c 'cd .. && ln -s ../.ssh k'; echo x >> ../k/authorized_keys`, "block"},
		{"X09", `bash -c "cd $X && ln -s ../.ssh k; echo x >> k/authorized_keys"`, "block"},
	}, "claudecode", "codex")
}

// A link call whose name is only entered with cd, beside known readers, is
// written where it stands; a size or path reader that names the SSH folder
// reads nothing it could change; a link moved into a real directory goes
// inside it (GAP-0091). A writer after the entering cd, a link to state and
// a copy of the SSH folder keep blocking.
func TestSelfProtLinkNameBesideReaders(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"R01", `ln -s / r; bash -c "cd r && ls"`, "allow"},
		{"R02", `ln -s /usr/lib lib; bash -c "cd src && /bin/ls"`, "allow"},
		{"R03", `ln -s ordinary od; bash -c "cd od && cat o.txt"`, "allow"},
		{"R05", `du -sh ~/.ssh/`, "allow"},
		{"R06", `readlink -f ~/.ssh`, "allow"},
		{"R17", `ln -s ordinary od; bash -c "cd ~nosuchuser9 && ls"`, "allow"},
		{"R18", `du -sh ~/.*/`, "allow"},
		{"R19", `ln -s /usr/lib lib; ls ~nosuchuser9; bash -c "cd lib && ls"`, "block"},
		{"R07", `ln -s / r; bash -c "cd r && touch x"`, "block"},
		{"R08", `ln -s / r; bash -c "cd r && sed -i s/a/b/ x"`, "block"},
		{"R09", `ln -s / r; bash -c "cd r && ./run.sh"`, "block"},
		{"R10", `ln -s / r; bash -c "cd r && ls"; echo k >> r/home/alice/.ssh/authorized_keys`, "block"},
		{"R11", `ln -s / r; bash -c "cd r && ls"; mv a.txt r`, "block"},
		{"R12", `ln -s ../.ssh ks; bash -c "cd ks && cat authorized_keys"`, "block"},
		{"R13", `ln -s ~/.ssh/authorized_keys k; mv k build/; echo x >> build/k`, "block"},
		{"R14", `du -sh ~/.ssh/ > ~/.ssh/authorized_keys`, "block"},
	}, "claudecode", "codex")
}

// A move onto a real directory goes inside it, so the link moved into the
// directory it points into is followed. A gateway that cannot read the user's
// home cannot tell a directory from a link to one and keeps the unread
// reading (GAP-0091).
func TestSelfProtMoveIntoRealDirectory(t *testing.T) {
	for _, r := range []selfProtRow{
		{"M01", `ln -s build/out bin; mv bin build/`, "allow"},
		{"M02", `ln -s build/out bin; mv bin build`, "allow"},
		{"M03", `ln -s ~/.ssh/authorized_keys k; mv k build/; echo x >> build/k`, "block"},
		{"M05", `ln -s build/out bin; mv bin ../.ssh/`, "block"},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			if got := selfProtVerdict(t, r, false, connector); got != r.want {
				t.Errorf("%s per-user %s: %q = %s, want %s", r.id, connector, r.cmd, got, r.want)
			}
		}
	}
}
