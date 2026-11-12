// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hooklayout"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// perUserAccountHome is the account database's home, independent of the
// agent's HOME and DEFENSECLAW_HOME. Directory accounts use NSS when needed.
var perUserAccountHome = func() string {
	uid := os.Getuid()
	if account, err := user.LookupId(strconv.Itoa(uid)); err == nil && account != nil && filepath.IsAbs(account.HomeDir) {
		return filepath.Clean(account.HomeDir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	account, err := unixidentity.Default(ctx).LookupUID(uid)
	if err != nil || !filepath.IsAbs(account.Home) {
		return ""
	}
	return filepath.Clean(account.Home)
}

// perUserRecordHomes names the few homes that can hold this account's PID
// record. The installed hook's data store can differ from that home after a
// data_dir move. ClassifyPerUserListener still requires a strong PID record
// and a matching live process before any candidate yields a root diagnosis.
func perUserRecordHomes(opts Options) []string {
	if opts.Home == "" {
		return nil
	}
	homes := []string{opts.Home}
	seen := map[string]bool{filepath.Clean(opts.Home): true}
	add := func(home string) {
		if !filepath.IsAbs(home) {
			return
		}
		home = filepath.Clean(home)
		if !seen[home] {
			homes = append(homes, home)
			seen[home] = true
		}
	}
	if accountHome := perUserAccountHome(); accountHome != "" {
		add(filepath.Join(accountHome, ".defenseclaw"))
	}
	// The folder the gateway recorded as holding gateway.pid, independent of
	// where its config file sits, then the config folder for hooks rendered
	// before that record existed, then the environment status itself reads.
	add(hooklayout.RecordedInstallHome(opts.Home))
	if recorded := hooklayout.RecordedConfig(opts.Home); recorded != "" {
		add(filepath.Dir(recorded))
	}
	add(os.Getenv("DEFENSECLAW_HOME"))
	return homes
}
