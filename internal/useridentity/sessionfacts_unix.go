// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package useridentity

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	kcmDialTimeout = 200 * time.Millisecond
	kcmCallTimeout = 300 * time.Millisecond
	krb5ConfPath   = "/etc/krb5.conf"
	maxKrb5Conf    = 256 << 10
)

func currentSessionFactsHeader(now time.Time) string {
	ccname := ccacheNameFromEnv(os.Getenv)
	kind, residual := SplitCCacheName(ccname)
	mtime := ccacheModTime(kind, residual)
	key := strings.Join([]string{
		ccname, mtime, os.Getenv("XDG_SESSION_ID"), os.Getenv("SSH_CONNECTION"), os.Getenv("SSH_TTY"),
	}, "|")
	cachePath := ""
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		cachePath = filepath.Join(home, ".defenseclaw", SessionFactsCacheFileName)
		if header, ok := cachedSessionFactsHeader(cachePath, key, now); ok {
			return header
		}
	}
	facts := SessionFromSSHEnv(os.Getenv)
	principal, ccType := readDefaultPrincipal(kind, residual)
	facts.KerberosPrincipal, facts.CCacheType = principal, ccType
	if facts.Kind == "" && !facts.Empty() {
		facts.Kind = SessionLocal
	}
	header := EncodeSessionFactsHeader(ClaimedSessionHeader{Session: facts})
	if cachePath != "" {
		_ = writeSessionFactsCache(cachePath, key, header, now)
	}
	return header
}

// ccacheNameFromEnv is KRB5CCNAME, else the krb5.conf default_ccache_name,
// else the platform default (API: on macOS, FILE:/tmp/krb5cc_<uid>
// elsewhere).
func ccacheNameFromEnv(getenv func(string) string) string {
	if name := strings.TrimSpace(getenv("KRB5CCNAME")); name != "" {
		return name
	}
	if name := krb5ConfDefaultCCacheName(krb5ConfPath, 0); name != "" {
		return expandCCacheName(name)
	}
	if runtime.GOOS == "darwin" {
		return "API:"
	}
	return "FILE:/tmp/krb5cc_" + strconv.Itoa(os.Getuid())
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
// returns the cache type even when the principal cannot be read.
func readDefaultPrincipal(kind, residual string) (principal, ccType string) {
	switch kind {
	case CCacheFile:
		return readFileCCachePrincipal(residual), CCacheFile
	case CCacheDir:
		return readDirCCachePrincipal(residual), CCacheDir
	case CCacheKCM:
		return readKCMPrincipal(residual), CCacheKCM
	case CCacheKeyring:
		return "", CCacheKeyring
	case CCacheAPI:
		return "", CCacheAPI
	}
	return "", ""
}

func readFileCCachePrincipal(path string) string {
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return ""
	}
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
	data, err := os.ReadFile(filepath.Join(residual, "primary"))
	if err != nil || len(data) > 256 {
		return ""
	}
	name := strings.TrimSpace(string(data))
	if name == "" || strings.ContainsAny(name, "/\\") {
		return ""
	}
	return readFileCCachePrincipal(filepath.Join(residual, name))
}

func readKCMPrincipal(cacheName string) string {
	for _, socket := range []string{DefaultKCMSocketPath, LegacyKCMSocketPath} {
		conn, err := net.DialTimeout("unix", socket, kcmDialTimeout)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(kcmCallTimeout))
		principal, err := KCMDefaultPrincipal(conn, cacheName)
		_ = conn.Close()
		if err == nil {
			return principal
		}
		return ""
	}
	return ""
}
