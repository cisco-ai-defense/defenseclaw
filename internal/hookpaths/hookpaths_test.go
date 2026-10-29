// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRedirectOnlyStatementsDoNotPanic(t *testing.T) {
	for _, tc := range []struct{ id, command string }{
		{"PAN-0001", "> proj/out/build.log"},
		{"PAN-0002", "> proj/out/build.log && echo done"},
		{"PAN-0003", "> /tmp/x.log"},
		{"PAN-0004", ": > proj/out/build.log"},
		{"PAN-0005", "true && > proj/out/build.log"},
		{"PAN-0006", "  >> proj/out/build.log"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{
				"tool_name": "Bash", "cwd": "/home/test",
				"tool_input": map[string]string{"command": tc.command},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := Decode(Resolve(payload)); !ok {
				t.Fatal("resolver returned no decodable proof")
			}
		})
	}
}

// A hard link is compared by file identity (inode, or volume serial and file
// index on Windows), not by its own pathname.
func TestResolveHardLinkToAuthorizedKeys(t *testing.T) {
	// macOS keeps the temp dir under the /var -> /private/var link.
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link, other := filepath.Join(home, "hard.cfg"), filepath.Join(home, "notes.txt")
	if err := os.Link(keys, link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(home)
	for path, want := range map[string]string{link: keys, other: other} {
		payload, err := json.Marshal(map[string]any{"tool_name": "Write",
			"tool_input": map[string]any{"file_path": path, "content": "marker"}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(Resolve(payload))
		if !ok || targets[path] != want {
			t.Fatalf("target of %s = %q, want %q; all=%v", path, targets[path], want, targets)
		}
	}
}

// A wrapper in front of apply_patch still runs it with a patch the hook
// cannot read, so its targets are unknown; an unresolved wrapper that names
// apply_patch fails closed too (GAP-1428).
func TestApplyPatchBehindWrapperIsUnknown(t *testing.T) {
	for command, known := range map[string]bool{
		"env apply_patch < draft.patch": false,
		"echo '*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n*** End Patch'\napply_patch < staged.patch":        false,
		"printf '*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n*** End Patch'\ncat staged.patch | apply_patch":  false,
		"printf '*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n*** End Patch'; cat staged.patch | apply_patch":  false,
		"apply_patch '*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n*** End Patch'; APPLY_PATCH < staged.patch": false,
		"printf '*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n*** End Patch' | apply_patch < staged.patch":     false,
		"env FOO=1 apply_patch < draft.patch": false,
		// A body line that closes the feeding quote or here-document (GAP-1462).
		"echo '*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n'; apply_patch < staged.patch; echo '\n*** End Patch' | apply_patch":             false,
		"apply_patch <<'P'\n*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\nP\napply_patch < staged.patch\napply_patch <<'Q'\n*** End Patch\nQ": false,
		// Patch data inside the feed is not shell, the shell after it is (GAP-1489).
		"apply_patch <<'P'\n*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+apply_patch(\"x\")\n*** End Patch\nP\napply_patch < staged.patch":          false,
		"cat <<'+A'\napply_patch <<'P'\n*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+A\n+x; apply_patch < staged.patch\n*** End Patch\nP":           false,
		"x=\"$(echo ')\"\napply_patch <<'P'\n*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+y'; apply_patch < staged.patch; echo '\n*** End Patch\nP": false,
		// An expanding feed may carry other directives than the text shows, so
		// it binds no call and its visible targets do not count (GAP-1506).
		"apply_patch <<P\n*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n$EXTRA\n*** End Patch\nP": false,
		"apply_patch \"*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+$EXTRA\n*** End Patch\"":        false,
		"command apply_patch < draft.patch":          false,
		"exec apply_patch < draft.patch":             false,
		"nohup apply_patch < draft.patch":            false,
		"time apply_patch < draft.patch":             false,
		"nice -n 5 apply_patch < draft.patch":        false,
		"sudo apply_patch < draft.patch":             false,
		`sh -c "apply_patch < draft.patch"`:          false,
		"sudo --user root apply_patch < draft.patch": false,
		"time grep -rn apply_patch .":                true,
		"env FOO=1 make test":                        true,
	} {
		if targets, ok := ApplyPatchWriteTargets("Bash", nil, command, "", ""); ok != known || len(targets) != 0 {
			t.Errorf("%s: targets %v, known %v; want known %v", command, targets, ok, known)
		}
	}
}

func TestApplyPatchBoundEnvelopeInputs(t *testing.T) {
	cwd, want := "", "/tmp/notes.txt"
	if runtime.GOOS == "windows" {
		cwd, want = "C:\\work", "C:\\tmp\\notes.txt"
	}
	envelope := "*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n*** End Patch"
	// Patch lines that name apply_patch are data for the bound call (GAP-1489).
	code := "*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n apply_patch('ctx')\n-apply_patch(\"old\")\n+apply_patch(\"x\")\n*** End Patch"
	for _, command := range []string{
		"apply_patch <<'PATCH'\n" + code + "\nPATCH",
		"@'\n" + code + "\n'@ | apply_patch",
		"apply_patch <<'PATCH'\n" + envelope + "\nPATCH",
		"apply_patch <<< '" + envelope + "'",
		"apply_patch '" + envelope + "'",
		"echo '" + envelope + "' | apply_patch",
		"@'\n" + envelope + "\n'@ | apply_patch",
	} {
		targets, ok := ApplyPatchWriteTargets("Bash", nil, command, cwd, "")
		if !ok || len(targets) != 1 || targets[0] != want {
			t.Errorf("%q: targets %v, known %v", command, targets, ok)
		}
	}
	if runtime.GOOS == "windows" {
		for _, path := range []string{"C:/tmp/notes.txt", "\\\\server\\share\\notes.txt"} {
			envelope := "*** Begin Patch\n*** Update File: " + path + "\n@@\n+x\n*** End Patch"
			targets, ok := ApplyPatchWriteTargets("apply_patch", nil, envelope, "", "")
			if !ok || len(targets) != 1 || targets[0] != filepath.Clean(path) {
				t.Errorf("%q: targets %v, known %v", path, targets, ok)
			}
		}
		// A drive-relative path depends on per-drive process state, not cwd.
		envelope := "*** Begin Patch\n*** Update File: C:notes.txt\n@@\n+x\n*** End Patch"
		if targets, ok := ApplyPatchWriteTargets("apply_patch", nil, envelope, cwd, ""); ok || len(targets) != 0 {
			t.Errorf("drive-relative target: targets %v, known %v", targets, ok)
		}
	}
}

// A link that the command creates makes a later write through the new name a
// write to the linked file; a link the hook cannot read statically makes the
// write targets unknown (GAP-1505).
func TestResolveLinkCreatedInCommand(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	// An existing alias that ln -f replaces.
	notes := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(notes, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(home)
	for _, tc := range []struct{ command, operand, want string }{
		{"ln ~/.ssh/authorized_keys notes.txt && echo k >> notes.txt", "notes.txt", keys},
		{"ln -s ~/.ssh/authorized_keys notes.txt; echo k >> notes.txt", "notes.txt", keys},
		{"ln -f ~/.ssh/authorized_keys notes.txt\necho k >> notes.txt", "notes.txt", keys},
		{"ln -sf ../.ssh/authorized_keys sub/notes.txt; echo k >> sub/notes.txt", "sub/notes.txt", keys},
		{"ln -s ~/.ssh dir; echo k >> dir/authorized_keys", "dir/authorized_keys", keys},
		{"cp --link ~/.ssh/authorized_keys notes.txt; echo k >> notes.txt", "notes.txt", keys},
		{"ln ~/.ssh/authorized_keys notes.txt; mv notes.txt n2; echo k >> n2", "n2", ""},
		{"ln \"$SRC\" notes.txt; echo k >> notes.txt", "notes.txt", ""},
		{"python3 -c \"import os; os.link('a', 'notes.txt')\"; echo k >> notes.txt", "notes.txt", ""},
		{"echo k >> notes.txt", "notes.txt", notes},
		// A multicall binary runs its applet; archive and sync tools that
		// link files make the write targets unknown (GAP-1521).
		{"busybox ln ~/.ssh/autho\"\"rized_keys n1.txt && echo k >> n1.txt", "n1.txt", keys},
		{"toybox ln -s ~/.ssh/authorized_keys n1.txt; echo k >> n1.txt", "n1.txt", keys},
		// A static prefix wrapper runs its child here: the link it makes is
		// read as the plain one, so the write reaches the keys file
		// (RV-p3i3-1). A wrapper that moves the directory or the program
		// resolution keeps the link unknown.
		{"sudo busybox ln ~/.ssh/authorized_keys n1.txt; echo k >> n1.txt", "n1.txt", keys},
		{"nohup ln -s ~/.ssh/authorized_keys n1.txt; echo k >> n1.txt", "n1.txt", keys},
		{"sudo -i ln -s ~/.ssh/authorized_keys n1.txt; echo k >> n1.txt", "n1.txt", ""},
		{"env PATH=/tmp/bin ln -s ~/.ssh/authorized_keys n1.txt; echo k >> n1.txt", "n1.txt", ""},
		{"env -C sub ln -s ~/.ssh/authorized_keys n1.txt; echo k >> sub/n1.txt", "sub/n1.txt", ""},
		{"rsync -a --link-dest=$HOME/.ssh $HOME/.ssh/ d/; echo k >> d/autho\"\"rized_keys", "d/authorized_keys", ""},
		{"rsync -aH ~/.ssh/ d/; echo k >> d/authorized_keys", "d/authorized_keys", ""},
		{"ls ~/.ssh/authorized_keys | cpio -pdl d; echo k >> d/n1.txt", "d/n1.txt", ""},
		{"pax -rwl ~/.ssh d; echo k >> d/n1.txt", "d/n1.txt", ""},
		{"tar xf keys.tar; echo k >> n1.txt", "n1.txt", ""},
		// Ordinary commands keep their targets.
		{"ln notes.txt n2.txt && echo k >> n2.txt", "n2.txt", filepath.Join(home, "n2.txt")},
		{"rsync -a src/ d/ && echo k >> d/log.txt", "d/log.txt", filepath.Join(home, "d", "log.txt")},
		{"tar czf out.tgz src && echo k >> log.txt", "log.txt", filepath.Join(home, "log.txt")},
		{"busybox ls > list.txt", "list.txt", filepath.Join(home, "list.txt")},
	} {
		payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": home,
			"tool_input": map[string]any{"command": tc.command}})
		if err != nil {
			t.Fatal(err)
		}
		operand := filepath.Join(home, filepath.FromSlash(tc.operand))
		targets, ok := Decode(Resolve(payload))
		got, present := targets[operand]
		if !ok || !present || got != tc.want || (targets[TruncatedKey] == "1") != (tc.want == "") {
			t.Errorf("%q: target of %s = %q (present %v), want %q; all=%v", tc.command, operand, got, present, tc.want, targets)
		}
	}
}

// A ".." in a link target is interpreted after resolving the preceding
// component. A missing component remains unknown.
func TestRelativeLinkTargetDotDot(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{
		filepath.Join(home, ".ssh", "d"), filepath.Join(home, "a"),
		filepath.Join(home, "a2"), filepath.Join(home, "unpack", "q", "r"),
		filepath.Join(home, "ordinary"), filepath.Join(home, "shared"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range []struct{ name, target string }{
		{filepath.Join(home, "a", "b"), filepath.Join(home, ".ssh", "d")},
		{filepath.Join(home, "a", "l"), filepath.FromSlash("b/../authorized_keys")},
		{filepath.Join(home, "a2", "b"), filepath.FromSlash("../unpack/q/r")},
		{filepath.Join(home, "a2", "l"), filepath.FromSlash("b/../t")},
		{filepath.Join(home, "ordinary", "lib"), filepath.FromSlash("../shared")},
	} {
		if err := os.Symlink(link.target, link.name); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		name, path, want string
		known            bool
	}{
		{"keys hop", filepath.Join(home, "a", "l"), filepath.Join(home, ".ssh", "authorized_keys"), true},
		{"extractor hop", filepath.Join(home, "a2", "l"), filepath.Join(home, "unpack", "q", "t"), true},
		{"unknown hop", filepath.Join(home, "a", "missing") + string(filepath.Separator) + ".." + string(filepath.Separator) + "out", "", false},
		{"ordinary dot dot", filepath.Join(home, "ordinary") + string(filepath.Separator) + ".." + string(filepath.Separator) + "out", filepath.Join(home, "out"), true},
		{"ordinary link", filepath.Join(home, "ordinary", "lib", "x"), filepath.Join(home, "shared", "x"), true},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, ok := ResolveWriteTarget(row.path)
			if ok != row.known || ok && got != row.want {
				t.Errorf("resolved = %q, known %v; want %q, %v", got, ok, row.want, row.known)
			}
			_, formsOK := writePathForms(row.path, 0)
			if formsOK != row.known {
				t.Errorf("forms known = %v, want %v", formsOK, row.known)
			}
		})
	}
}

// The gateway may receive ENOENT from ProtectHome even for an existing link.
// Reported source facts must decide that case without relying on the host OS.
func TestReportedCopySourceLinkFactSurvivesInvisibleGateway(t *testing.T) {
	cwd, home := filepath.Join(t.TempDir(), "proj"), filepath.Join(t.TempDir(), "home")
	path := OperandPath("disklink", cwd)
	missing := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	for _, row := range []struct {
		fact string
		want bool
	}{
		{"1", true}, {"0", false}, {"?", true},
	} {
		facts := map[string]string{SourceLinkFactPrefix + path: row.fact}
		if got := diskSourceMayLink("disklink", cwd, home, facts, false, missing); got != row.want {
			t.Fatalf("reported fact %q with ENOENT = %v, want %v", row.fact, got, row.want)
		}
	}
}
