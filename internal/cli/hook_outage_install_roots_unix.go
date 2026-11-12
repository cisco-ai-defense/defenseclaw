// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hooklayout"
)

// outageAccountHome is this account's home folder from the account database
// (getpwuid), never from HOME: the folder the installer's default
// DEFENSECLAW_HOME (~/.defenseclaw) is in. Release builds have no cgo, so on
// Linux os/user reads /etc/passwd only and an account from SSSD, AD or LDAP
// is not found there (rel-1-0-6 GAP-0308); the account database is then
// asked through NSS with getent (nssAccountHome). It is "" when both
// lookups fail (an account no database lists), and then only the folders
// hookOutageInstallHeld reads from the environment stand in for it. The
// answer is looked up once per process (newOutageAccountHome): one decision
// gives one answer, and a hung NSS backend costs at most one bounded getent
// (2 s plus a 0.5 s wait). A variable for tests.
var outageAccountHome = newOutageAccountHome(lookupOutageAccountHome)

// newOutageAccountHome caches lookup's first answer for the process.
func newOutageAccountHome(lookup func() string) func() string {
	return sync.OnceValue(lookup)
}

func lookupOutageAccountHome() string {
	if filepath.IsAbs(outageAccountHomeBake) {
		return filepath.Clean(outageAccountHomeBake)
	}
	uid := os.Getuid()
	account, err := user.LookupId(strconv.Itoa(uid))
	if err == nil && account != nil && filepath.IsAbs(account.HomeDir) {
		return filepath.Clean(account.HomeDir)
	}
	// macOS os/user asks libc (directory and mobile accounts resolve).
	if runtime.GOOS != "linux" {
		return ""
	}
	return nssAccountHome(uid)
}

// outageGetentPaths are the fixed absolute paths of getent tried in order;
// outageGetentOwner is the account that must own getent and its folder
// (root). outageGetentTimeout bounds the lookup: a hung NSS backend closes
// the outage instead of holding the hook. Variables for tests.
var (
	outageGetentPaths   = []string{"/usr/bin/getent", "/bin/getent"}
	outageGetentOwner   = 0
	outageGetentTimeout = 2 * time.Second
)

// nssAccountHome is the home folder getent passwd UID names for uid: the
// first getent at a fixed path that exists, a regular file (not a link)
// owned by root in a root-owned folder, neither writable by group or others,
// run with a fixed environment and a short timeout. The entry must be one
// passwd line for that uid with an absolute, clean home that exists as a
// folder owned by uid. Any other answer is "", which closes the outage as
// before. HOME and the agent's PATH are never read.
func nssAccountHome(uid int) string {
	for _, path := range outageGetentPaths {
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if !trustedOutageBinary(path, info) {
			return ""
		}
		return getentHome(path, uid)
	}
	return ""
}

func trustedOutageBinary(path string, info os.FileInfo) bool {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || !ownedByUID(info, outageGetentOwner) {
		return false
	}
	dir, err := os.Stat(filepath.Dir(path))
	return err == nil && dir.IsDir() && dir.Mode().Perm()&0o022 == 0 && ownedByUID(dir, outageGetentOwner)
}

func getentHome(path string, uid int) string {
	ctx, cancel := context.WithTimeout(context.Background(), outageGetentTimeout)
	defer cancel()
	want := strconv.Itoa(uid)
	cmd := exec.CommandContext(ctx, path, "passwd", want)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.WaitDelay = 500 * time.Millisecond
	var out bytes.Buffer
	cmd.Stdout = &limitedBuffer{buf: &out, max: 4096}
	if err := cmd.Run(); err != nil || out.Len() == 0 || out.Len() >= 4096 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 1 {
		return ""
	}
	fields := strings.Split(lines[0], ":")
	if len(fields) != 7 || fields[2] != want {
		return ""
	}
	home := fields[5]
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return ""
	}
	info, err := os.Stat(home)
	if err != nil || !info.IsDir() || !ownedByUID(info, uid) {
		return ""
	}
	return home
}

// limitedBuffer keeps at most max bytes; one more byte marks the answer as
// too long (getentHome refuses it).
type limitedBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

func ownedByUID(info os.FileInfo, uid int) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && uid >= 0 && int(st.Uid) == uid
}

// outageAccountHomeBake is empty in every release build. The shell hook tests
// set it at link time (go build -ldflags -X) to an empty folder of their own,
// so the gateway binary they run does not read the build account's real
// ~/.defenseclaw: an install lock another test or build left there for a
// moment closed the outage of a hook test case at random
// (rel-1-0-6:GAP-0345). Nothing at run time can set it.
var outageAccountHomeBake string

// outageInstalledDataRoot is the data root of the installed runtime's
// protected install state. Linux and macOS per-user installs keep none, so
// install.sh holds a data_dir set apart from DEFENSECLAW_HOME itself
// (hold_hook_data_dir). A variable for tests.
var outageInstalledDataRoot = func() (string, bool) { return "", false }

// outageHomeEnvNames are the home variables whose ~/.defenseclaw
// hookOutageInstallHeld also looks in.
var outageHomeEnvNames = []string{"HOME"}

// outageRecordedConfig is shared with the native hook's diagnostic lookup.
// Keep the variable seam used by the outage-mode tests.
var outageRecordedConfig = hooklayout.RecordedConfig
