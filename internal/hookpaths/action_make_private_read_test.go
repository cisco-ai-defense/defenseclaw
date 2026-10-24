// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestGAP0994PrivateKeyReaderParity(t *testing.T) {
	// The physical directory: on macOS t.TempDir is under the /var link.
	posixHome, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	winHome, winCWD := `C:\Users\Alice`, `C:\Users\Alice\project`
	encode := func(command string) string {
		units := utf16.Encode([]rune(command))
		bytes := make([]byte, 2*len(units))
		for i, unit := range units {
			bytes[2*i], bytes[2*i+1] = byte(unit), byte(unit>>8)
		}
		return base64.StdEncoding.EncodeToString(bytes)
	}
	for _, tc := range []struct {
		name, command, cwd, home string
		block                    bool
	}{
		{"Windows head positive bytes", `head -c 4096 ~/.ssh/id_ed25519; echo done`, winCWD, winHome, true},
		{"Windows head zero bytes", `head -c 0 ~/.ssh/id_ed25519; echo done`, winCWD, winHome, true},
		{"Windows tail bytes", `tail -c 4096 /c/Users/Alice/.ssh/id_rsa`, winCWD, winHome, true},
		{"Windows sort reader", `sort /cygdrive/c/Users/Alice/.ssh/id_ecdsa`, winCWD, winHome, true},
		{"Windows wc reader", `wc %USERPROFILE%\.ssh\id_dsa`, winCWD, winHome, true},
		{"Windows HOME braces", `head -c 4096 ${HOME}/.ssh/id_ed25519`, winCWD, winHome, true},
		{"Windows PowerShell profile", `tail -c 4096 $env:USERPROFILE\.ssh\id_rsa`, winCWD, winHome, true},
		{"Windows home drive path", `head -c 4096 %HOMEDRIVE%%HOMEPATH%\.ssh\id_ed25519`, winCWD, winHome, true},
		{"Windows extended drive path", `head -c 4096 //?/C:/Users/Alice/.ssh/id_ed25519`, winCWD, winHome, true},
		{"Windows native path", `head -c 4096 C:\Users\Alice\.ssh\id_ed25519`, winCWD, winHome, true},
		{"Windows UNC home", `head -c 4096 ~/.ssh/id_ed25519`, `\\fileserver\users\Alice\project`, `\\fileserver\users\Alice`, true},
		{"Windows extended UNC path", `tail -c 4096 //?/UNC/fileserver/users/Alice/.ssh/id_rsa`, `\\fileserver\users\Alice\project`, `\\fileserver\users\Alice`, true},
		{"Windows env wrapper", `env head -c 4096 ~/.ssh/id_ed25519`, winCWD, winHome, true},
		{"Windows nice wrapper", `nice -n 5 tail -c 4096 ~/.ssh/id_ed25519`, winCWD, winHome, true},
		{"Windows timeout wrapper", `timeout 5 head -c 4096 ~/.ssh/id_ed25519`, winCWD, winHome, true},
		{"Windows bash command", `bash -c 'head -c 4096 ~/.ssh/id_ed25519'`, winCWD, winHome, true},
		{"Windows cmd command", `cmd /c "head -c 4096 ~/.ssh/id_ed25519"`, winCWD, winHome, true},
		{"Windows PowerShell command", `pwsh -Command 'head -c 4096 ~/.ssh/id_ed25519'`, winCWD, winHome, true},
		{"Windows PowerShell encoded command", `pwsh -EncodedCommand ` + encode(`head -c 4096 ~/.ssh/id_ed25519`), winCWD, winHome, true},
		{"Windows public key", `head -c 4096 ~/.ssh/id_ed25519.pub`, winCWD, winHome, false},
		{"Windows authorized keys read", `cat ~/.ssh/authorized_keys`, winCWD, winHome, false},
		{"Windows ssh identity", `ssh -i ~/.ssh/id_ed25519 host.example`, winCWD, winHome, false},
		{"Windows ssh-keygen identity", `ssh-keygen -y -f ~/.ssh/id_ed25519`, winCWD, winHome, false},
		{"POSIX head positive bytes", `head -c 4096 ~/.ssh/id_ed25519; echo done`, posixHome, posixHome, true},
		{"POSIX head zero bytes", `head -c 0 ~/.ssh/id_ed25519; echo done`, posixHome, posixHome, true},
		{"POSIX tail bytes", `tail -c 4096 ~/.ssh/id_rsa`, posixHome, posixHome, true},
		{"POSIX sort reader", `sort ~/.ssh/id_ecdsa`, posixHome, posixHome, true},
		{"POSIX wc reader", `wc ~/.ssh/id_dsa`, posixHome, posixHome, true},
		{"POSIX grep reader", `grep marker ~/.ssh/id_ed25519`, posixHome, posixHome, true},
		{"POSIX public key", `head -c 4096 ~/.ssh/id_ed25519.pub`, posixHome, posixHome, false},
		{"POSIX authorized keys read", `cat ~/.ssh/authorized_keys`, posixHome, posixHome, false},
		{"POSIX ssh identity", `ssh -i ~/.ssh/id_ed25519 host.example`, posixHome, posixHome, false},
		{"POSIX ssh-keygen identity", `ssh-keygen -y -f ~/.ssh/id_ed25519`, posixHome, posixHome, false},
		{"POSIX type lookup", `type ~/.ssh/id_ed25519`, posixHome, posixHome, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "POSIX type lookup" && actionWindowsHome(tc.home) {
				t.Skip("a Windows temporary home selects the Windows grammar, where type reads a file")
			}
			if got := ActionCommandDecision(tc.command, tc.cwd, tc.home); (got != "") != tc.block {
				t.Fatalf("decision=%q, want block=%t", got, tc.block)
			}
		})
	}
}

// gap0996Fixture lays out a home with an authorized_keys file, a project,
// and makefiles inside and outside the project. On Windows the temporary
// home is a drive path, so the same rows exercise the Windows grammar.
func gap0996Fixture(t *testing.T) (home, cwd string, links bool) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cwd = filepath.Join(home, "project")
	for _, dir := range []string{cwd, filepath.Join(cwd, "build"), filepath.Join(home, ".ssh"),
		filepath.Join(home, "lib"), filepath.Join(home, "evil"), filepath.Join(home, "inc")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(home, ".ssh", "authorized_keys")
	writeKey := "write-key:\n\tprintf 'fixture\\n' >> $(HOME)/.ssh/authorized_keys\n"
	for name, content := range map[string]string{
		key:                                     "fixture\n",
		filepath.Join(home, "writer.mk"):        writeKey,
		filepath.Join(home, "common.mk"):        "safe:\n\tprintf 'ok\\n' > report.txt\n",
		filepath.Join(home, "lib", "Makefile"):  "all:\n\tprintf 'ok\\n' > lib.txt\n",
		filepath.Join(home, "evil", "Makefile"): writeKey,
		filepath.Join(home, "inc", "evil.mk"):   writeKey,
		filepath.Join(cwd, "Makefile"):          "safe:\n\tprintf 'ok\\n' > report.txt\n",
		filepath.Join(cwd, "build", "Makefile"): "all:\n\tprintf 'ok\\n' > build.txt\n",
	} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links = os.Symlink(key, filepath.Join(cwd, "disklink")) == nil
	return home, cwd, links
}

func TestGAP0996MakeInspectionDecision(t *testing.T) {
	home, cwd, links := gap0996Fixture(t)
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"outside -f protected recipe", `make -f ../writer.mk write-key`, true},
		{"outside --file", `gmake --file=../writer.mk write-key`, true},
		{"outside --makefile", `make --makefile=../writer.mk write-key`, true},
		{"grouped short -kf", `make -kf ../writer.mk write-key`, true},
		{"absolute -f", `make -f ` + filepath.ToSlash(filepath.Join(home, "writer.mk")) + ` write-key`, true},
		{"home -f", `make -f ~/writer.mk write-key`, true},
		{"outside -C protected Makefile", `make -C ../evil write-key`, true},
		{"outside --directory", `make --directory=../evil write-key`, true},
		{"computed makefile name", `make -f "$UNKNOWN_MAKEFILE" safe`, true},
		{"makefile on stdin", `make -f - safe`, true},
		{"MAKEFILES shell assignment", `MAKEFILES=../writer.mk make write-key`, true},
		{"MAKEFILES env wrapper", `env MAKEFILES=../writer.mk make write-key`, true},
		{"computed MAKEFILES", `MAKEFILES="$X" make safe`, true},
		{"MAKEFLAGS shell assignment", `MAKEFLAGS=-f../writer.mk make write-key`, true},
		{"MAKEFLAGS command-line override", `make MAKEFLAGS=-f../writer.mk write-key`, true},
		{"eval text", `make --eval='x: ; printf k >> ~/.ssh/authorized_keys' x`, true},
		{"unused variable override", `make safe CC='sh -c "cat k >> ~/.ssh/authorized_keys"'`, false},
		{"make through nice", `nice -n 5 make -f ../writer.mk write-key`, true},
		{"make through timeout", `timeout 5 make -C ../evil write-key`, true},
		{"make through shell", `sh -c 'make -f ../writer.mk write-key'`, true},
		{"make through env -C", `env -C ../evil make write-key`, true},
		{"local ordinary Makefile", `make safe`, false},
		{"local default goal", `make`, false},
		{"MAKEFILES target not built", `MAKEFILES=../writer.mk make safe`, false},
		{"local make -C build", `make -C build all`, false},
		{"local env -C build", `env -C build make all`, false},
		{"benign outside makefile", `make -f ../common.mk safe`, false},
		{"benign outside -C", `make -C ../lib all`, false},
		{"MAKEFLAGS jobs", `MAKEFLAGS=-j8 make safe`, false},
		{"MAKEFLAGS letters", `MAKEFLAGS=ks make safe`, false},
		{"jobs option", `make -j8 safe`, false},
		{"compiler override", `make CC=clang safe`, false},
		{"target after --", `make -- -ftarget`, false},
		{"MAKEFILES for another command", `env MAKEFILES=../writer.mk echo ok`, false},
		{"missing Makefile", `make -C build/missing all`, false},
		{"missing outside makefile", `make -f ../missing.mk all`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, cwd, home); (got != "") != tc.block {
				t.Fatalf("decision=%q, want block=%t", got, tc.block)
			}
		})
	}
	makefile := func(t *testing.T, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, command, content string
		block, link            bool
	}{
		{"outside include", "make", "include ../writer.mk\nsafe:\n\t@true\n", true, false},
		{"outside tab include", "make write-key", "-include\t../writer.mk\nsafe:\n\t@true\n", true, false},
		{"include through a static variable", "make write-key", "PARTS := ../writer.mk\ninclude $(PARTS)\nsafe:\n\t@true\n", true, false},
		{"include through a glob", "make write-key", "include ../evil/Make*\nsafe:\n\t@true\n", true, false},
		{"include found through -I", "make -I ../inc write-key", "include evil.mk\nsafe:\n\t@true\n", true, false},
		{"recipe through a protected link", "make", "write-key:\n\tprintf 'fixture\\n' >> disklink\n", true, true},
		{"make HOME spelling $(HOME)", "make", "write-key:\n\tprintf ok >> $(HOME)/.ssh/authorized_keys\n", true, false},
		{"make HOME spelling ${HOME}", "make", "write-key:\n\tprintf ok >> ${HOME}/.ssh/authorized_keys\n", true, false},
		{"make HOME spelling $$HOME", "make", "write-key:\n\tprintf ok >> $$HOME/.ssh/authorized_keys\n", true, false},
		{"tilde recipe", "make", "write-key:\n\tprintf ok >> ~/.ssh/authorized_keys\n", true, false},
		{"continued recipe", "make", "write-key:\n\tprintf ok \\\n\t  >> ~/.ssh/authorized_keys\n", true, false},
		{"recipe on the rule line", "make", "write-key: ; printf ok >> ~/.ssh/authorized_keys\n", true, false},
		{"prerequisite of the goal", "make safe", "safe: write-key\n\t@true\nwrite-key:\n\tprintf ok >> ~/.ssh/authorized_keys\n", true, false},
		{"pattern rule", "make out.txt", "%.txt:\n\tprintf ok >> ~/.ssh/authorized_keys\n", true, false},
		{"parse-time shell", "make safe", "X := $(shell printf ok >> ~/.ssh/authorized_keys)\nsafe:\n\t@true\n", true, false},
		{"default goal variable", "make", "safe:\n\t@true\nwrite-key:\n\tprintf ok >> ~/.ssh/authorized_keys\n.DEFAULT_GOAL := write-key\n", true, false},
		{"other target writes a protected file", "make safe", "write-key:\n\tprintf ok >> ~/.ssh/authorized_keys\nsafe:\n\tprintf ok > report.txt\n", false, false},
		{"included target not built", "make safe", "include ../writer.mk\nsafe:\n\t@true\n", false, false},
		{"local include", "make safe", "include parts.mk\n", false, false},
		{"computed dependency include", "make safe", "SRCS := a.c b.c\n-include $(SRCS:.c=.d)\nsafe:\n\t@true\n", false, false},
		{"shell include", "make safe", "-include $(shell ls *.dep)\nsafe:\n\t@true\n", false, false},
		{"many variables", "make safe", strings.Repeat("ITEM := ordinary\n", 600) + "safe:\n\t@true\n", false, false},
		{"long continued source list", "make safe", "SRCS = " + strings.Repeat("src/file.c \\\n  ", 700) + "main.c\nsafe:\n\t@true\n", false, false},
		{"ordinary HOME variable", "make safe", "HOME_DIR := $(HOME)\nsafe:\n\tprintf ok > report.txt\n", false, false},
		{"deploy with an ssh identity", "make deploy", "deploy:\n\tscp -i ~/.ssh/id_ed25519 dist/app host.example:/srv\n", false, false},
		{"large ordinary Makefile beyond the script bound", "make safe", strings.Repeat("# ordinary comment\n", 60000) + "safe:\n\t@true\n", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.link && !links {
				t.Skip("symbolic links need a privilege this host does not grant")
			}
			makefile(t, tc.content)
			if err := os.WriteFile(filepath.Join(cwd, "parts.mk"), []byte("safe:\n\t@true\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := ActionCommandDecision(tc.command, cwd, home); (got != "") != tc.block {
				t.Fatalf("decision=%q, want block=%t", got, tc.block)
			}
		})
	}
	t.Run("symlinked local Makefile", func(t *testing.T) {
		if !links {
			t.Skip("symbolic links need a privilege this host does not grant")
		}
		dir := filepath.Join(cwd, "linked")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "real.mk"), []byte("all:\n\t@true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real.mk", filepath.Join(dir, "Makefile")); err != nil {
			t.Fatal(err)
		}
		if got := ActionCommandDecision("make -C linked all", cwd, home); got != "" {
			t.Fatalf("symlinked ordinary Makefile blocked: %q", got)
		}
	})
	t.Run("makefile over the read bound", func(t *testing.T) {
		huge := filepath.Join(home, "huge.mk")
		if err := os.WriteFile(huge, make([]byte, maxMakeSourceBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := ActionCommandDecision("make -f ../huge.mk all", cwd, home); got == "" {
			t.Fatal("a makefile the hook cannot read whole was allowed")
		}
	})
	t.Run("makefile that is not a regular file", func(t *testing.T) {
		if got := ActionCommandDecision("make -f ../lib all", cwd, home); got == "" {
			t.Fatal("a directory named as the makefile was allowed")
		}
	})
}
