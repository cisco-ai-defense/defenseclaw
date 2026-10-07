// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package useridentity

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	kcmDialTimeout = 200 * time.Millisecond
	// kcmCallTimeout covers a socket-activated sssd-kcm starting after its
	// idle exit, which took about 0.4 s on RHEL 9; a running KCM answers in
	// milliseconds.
	kcmCallTimeout = 2 * time.Second
	krb5ConfPath   = "/etc/krb5.conf"
	maxKrb5Conf    = 256 << 10
	// macOS's own Heimdal klist reads the API: cache; it answers in about
	// 15 ms and gets the same bound as a KCM call.
	macOSKlistPath = "/usr/bin/klist"
	klistTimeout   = kcmCallTimeout
	maxKlistOutput = 64 << 10
	klistWaitDelay = 100 * time.Millisecond
	// sessionFactsDeadline bounds the whole read; the KCM call and klist
	// finish well inside it.
	sessionFactsDeadline = kcmCallTimeout + time.Second
)

// currentSessionFactsHeader gives up after sessionFactsDeadline and sends the
// session variables alone. A credential cache, or the home holding the facts
// cache, on a network or FUSE mount that stopped answering blocks in the
// kernel, where nothing can interrupt it; that read is left to finish on its
// own, so the hook still answers inside the agent's deadline.
func currentSessionFactsHeader(now time.Time) string {
	done := make(chan string, 1)
	go func() { done <- readSessionFactsHeader(now) }()
	timer := time.NewTimer(sessionFactsDeadline)
	defer timer.Stop()
	select {
	case header := <-done:
		return header
	case <-timer.C:
		return EncodeSessionFactsHeader(ClaimedSessionHeader{Session: SessionFromSSHEnv(os.Getenv)})
	}
}

func readSessionFactsHeader(now time.Time) string {
	ccname, platformDefault := ccacheNameFromEnv(os.Getenv)
	kind, residual := SplitCCacheName(ccname)
	mtime := ccacheModTime(kind, residual)
	key := strings.Join([]string{
		ccname, mtime, os.Getenv("XDG_SESSION_ID"), os.Getenv("SSH_CONNECTION"), os.Getenv("SSH_TTY"),
	}, "|")
	envKey := SessionFactsEnvKey(os.Getenv)
	cachePath := ""
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		cachePath = filepath.Join(home, ".defenseclaw", SessionFactsCacheFileName)
		if header, ok := cachedSessionFactsHeader(cachePath, key, envKey, now); ok {
			return header
		}
	}
	facts := SessionFromSSHEnv(os.Getenv)
	principal, ccType, settled := readDefaultPrincipal(kind, residual)
	if principal == "" && (ccType != CCacheKeyring || platformDefault) {
		// No readable cache: report no type rather than the default name's.
		ccType = ""
	}
	facts.KerberosPrincipal, facts.CCacheType = principal, ccType
	if facts.Kind == "" && !facts.Empty() {
		facts.Kind = SessionLocal
	}
	header := EncodeSessionFactsHeader(ClaimedSessionHeader{Session: facts})
	if cachePath != "" {
		written := now
		if !settled {
			// A KCM read that failed in transit, or a klist that timed out,
			// is not the session's answer: it is reused for
			// sessionFactsRetryAfter, not the TTL.
			written = now.Add(sessionFactsRetryAfter - SessionFactsCacheTTL)
		}
		_ = writeSessionFactsCache(cachePath, key, envKey, header, written)
	}
	return header
}

// ccacheNameFromEnv is KRB5CCNAME, else the krb5.conf default_ccache_name,
// else the platform default (API: on macOS, FILE:/tmp/krb5cc_<uid>
// elsewhere); platformDefault reports the last case. A KEYRING: cache
// cannot be read, so its type is reported only when the user or the
// administrator named it.
func ccacheNameFromEnv(getenv func(string) string) (name string, platformDefault bool) {
	if name := strings.TrimSpace(getenv("KRB5CCNAME")); name != "" {
		return name, false
	}
	if name := krb5ConfDefaultCCacheName(krb5ConfPath, 0); name != "" {
		return expandCCacheName(name), false
	}
	if runtime.GOOS == "darwin" {
		return "API:", true
	}
	return "FILE:/tmp/krb5cc_" + strconv.Itoa(os.Getuid()), true
}

// krb5ConfDefaultCCacheName reads default_ccache_name from the [libdefaults]
// section of a krb5.conf and the files it includes, in reading order. Like
// MIT for a single-valued relation, the first value found wins.
func krb5ConfDefaultCCacheName(path string, depth int) string {
	if depth > 3 {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, maxKrb5Conf))
	section := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "includedir ") {
			dir := strings.TrimSpace(strings.TrimPrefix(line, "includedir "))
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !krb5IncludeName(entry.Name()) {
					continue
				}
				if name := krb5ConfDefaultCCacheName(filepath.Join(dir, entry.Name()), depth+1); name != "" {
					return name
				}
			}
			continue
		}
		if strings.HasPrefix(line, "include ") {
			if name := krb5ConfDefaultCCacheName(strings.TrimSpace(strings.TrimPrefix(line, "include ")), depth+1); name != "" {
				return name
			}
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[] ")
			continue
		}
		if section != "libdefaults" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(key) == "default_ccache_name" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// krb5IncludeName mirrors MIT's includedir filter: names of letters,
// digits, dashes and underscores, or ending in .conf.
func krb5IncludeName(name string) bool {
	if strings.HasSuffix(name, ".conf") {
		return true
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return name != ""
}

// expandCCacheName expands the krb5.conf tokens a default ccache name uses.
func expandCCacheName(name string) string {
	uid := strconv.Itoa(os.Getuid())
	replacer := strings.NewReplacer(
		"%{uid}", uid, "%{euid}", strconv.Itoa(os.Geteuid()), "%{USERID}", uid,
		"%{TEMP}", os.TempDir(), "%{null}", "",
	)
	return replacer.Replace(name)
}

func ccacheModTime(kind, residual string) string {
	path := ""
	switch kind {
	case CCacheFile:
		path = residual
	case CCacheDir:
		path = strings.TrimPrefix(residual, ":")
	}
	if path == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return strconv.FormatInt(info.ModTime().UnixNano(), 10)
}

// readDefaultPrincipal reads the default principal of the named cache. It
// returns the cache type even when the principal cannot be read; settled is
// false when a KCM read failed in transit or klist timed out, and may answer
// on a retry.
func readDefaultPrincipal(kind, residual string) (principal, ccType string, settled bool) {
	switch kind {
	case CCacheFile:
		return readFileCCachePrincipal(residual), CCacheFile, true
	case CCacheDir:
		return readDirCCachePrincipal(residual), CCacheDir, true
	case CCacheKCM:
		principal, settled = readKCMPrincipal(residual)
		return principal, CCacheKCM, settled
	case CCacheKeyring:
		return "", CCacheKeyring, true
	case CCacheAPI:
		principal, settled = readAPIPrincipal(residual)
		return principal, CCacheAPI, settled
	}
	return "", "", true
}

// readAPIPrincipal asks macOS's klist for the default principal of the API:
// cache, or of the named one. It runs as the hook's user with a bare
// environment, so it reads only that user's caches; a missing cache, no
// ticket or an older klist without --json settles on no principal, and only
// a timeout does not. Other systems have no API: cache.
func readAPIPrincipal(cacheName string) (principal string, settled bool) {
	if runtime.GOOS != "darwin" {
		return "", true
	}
	args := []string{"--json"}
	if cacheName != "" {
		args = append(args, "--cache="+CCacheAPI+":"+cacheName)
	}
	ctx, cancel := context.WithTimeout(context.Background(), klistTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, macOSKlistPath, args...)
	env := []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	if home, err := os.UserHomeDir(); err == nil {
		env = append(env, "HOME="+home)
	}
	cmd.Env = env
	out := &cappedBuffer{limit: maxKlistOutput}
	cmd.Stdout = out
	cmd.WaitDelay = klistWaitDelay
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", false
	}
	if err != nil {
		return "", true
	}
	return parseKlistJSONPrincipal(out.data), true
}

// cappedBuffer keeps the first limit bytes written to it and drops the rest,
// so a cache with many tickets cannot make the hook buffer without bound.
// It has no ReadFrom, so io.Copy goes through Write.
type cappedBuffer struct {
	data  []byte
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - len(c.data); room > 0 {
		c.data = append(c.data, p[:min(len(p), room)]...)
	}
	return len(p), nil
}

// openRegularFile opens path for reading if it is a regular file, or returns
// nil. The path comes from the user's KRB5CCNAME: opened non-blocking, a
// FIFO with no writer cannot hold the hook, and the type is checked on the
// open descriptor, so a path swapped after a check cannot either.
func openRegularFile(path string) *os.File {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil
	}
	return file
}

func readFileCCachePrincipal(path string) string {
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	file := openRegularFile(path)
	if file == nil {
		return ""
	}
	defer file.Close()
	principal, err := ParseFileCCachePrincipal(file)
	if err != nil {
		return ""
	}
	return principal
}

// readDirCCachePrincipal handles DIR:<dir> (the collection's primary file
// names the current cache) and DIR::<file> (one cache of a collection).
func readDirCCachePrincipal(residual string) string {
	if strings.HasPrefix(residual, ":") {
		return readFileCCachePrincipal(strings.TrimPrefix(residual, ":"))
	}
	file := openRegularFile(filepath.Join(residual, "primary"))
	if file == nil {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(file, 257))
	_ = file.Close()
	if err != nil || len(data) > 256 {
		return ""
	}
	name := strings.TrimSpace(string(data))
	if name == "" || strings.ContainsAny(name, "/\\") {
		return ""
	}
	return readFileCCachePrincipal(filepath.Join(residual, name))
}

// readKCMPrincipal asks the first KCM socket that accepts for the default
// principal. No socket accepting settles the answer (no KCM on this host);
// a dial or call that timed out or broke off does not (kcmReadSettled).
func readKCMPrincipal(cacheName string) (principal string, settled bool) {
	settled = true
	for _, socket := range []string{DefaultKCMSocketPath, LegacyKCMSocketPath} {
		conn, err := net.DialTimeout("unix", socket, kcmDialTimeout)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				settled = false
			}
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(kcmCallTimeout))
		principal, err = KCMDefaultPrincipal(conn, cacheName)
		_ = conn.Close()
		if err != nil {
			return "", kcmReadSettled(err)
		}
		return principal, true
	}
	return "", settled
}
