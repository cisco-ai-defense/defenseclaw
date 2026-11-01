// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
)

const (
	imageStoreMaxBytes = 4 << 20 // The image.Store limit; reading must never create its lock or owner.
	imageRemoveTimeout = 10 * time.Minute
	imageNameLimit     = 8
	imageWarningLimit  = 32
)

var (
	sandboxImageOwnerRE = lazyregexp.New(`^[0-9a-f]{16}$`)
	sandboxImageIDRE    = lazyregexp.New(`^sha256:[0-9a-f]{64}$`)
	sandboxImageRefRE   = lazyregexp.New(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	dockerAddressRE     = lazyregexp.New(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
	dockerUnixSocketRE  = lazyregexp.New(`unix:///[a-zA-Z0-9_./-]+`)
	dockerUnixQueryRE   = lazyregexp.New(`unix:///[a-zA-Z0-9_./-]+[?#]`)
)

type sandboxImageStore struct {
	Version int    `json:"version"`
	Owner   string `json:"owner"`
	Images  []struct {
		Tag string `json:"tag"`
	} `json:"images"`
	RunImages []struct {
		Tag   string `json:"tag"`
		Alias bool   `json:"alias"`
	} `json:"run_images"`
}

type sandboxDockerImage struct {
	tag  string
	id   string
	rank int // run image, alias, overlay image
}

// openSandboxImageHome opens the account-owned home like the rest of the purge.
// The home itself cannot be a symlink; walkDirs checks the folders below it.
func (e *Env) openSandboxImageHome(a SandboxAccount) (int, error) {
	path := filepath.Clean(e.P(a.Home))
	if !filepath.IsAbs(path) || path == "/" || a.UID <= 0 {
		return -1, errors.New("invalid account home")
	}
	fd, err := e.openHome(a)
	if err != nil {
		return -1, fmt.Errorf("account home: %w", err)
	}
	if fd < 0 {
		return -1, os.ErrNotExist
	}
	return fd, nil
}

// readSandboxImageStore reads only the owner and tag roles. It never creates
// images.json or its lock, and only reads a regular file owned by the account.
func (e *Env) readSandboxImageStore(a SandboxAccount, rel string) (sandboxImageStore, bool, error) {
	home, err := e.openSandboxImageHome(a)
	if err != nil {
		return sandboxImageStore{}, !errors.Is(err, os.ErrNotExist), err
	}
	defer unix.Close(home)
	parent, name, err := walkDirs(home, rel, a.UID)
	if err != nil || parent < 0 {
		return sandboxImageStore{}, err != nil, err
	}
	defer unix.Close(parent)
	var before unix.Stat_t
	if err := unix.Fstatat(parent, name, &before, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return sandboxImageStore{}, false, nil
	} else if err != nil {
		return sandboxImageStore{}, true, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || int(before.Uid) != a.UID {
		return sandboxImageStore{}, true, errors.New("images.json is not a regular file owned by the account")
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return sandboxImageStore{}, false, nil
	}
	if err != nil {
		return sandboxImageStore{}, true, fmt.Errorf("open images.json: %w", err)
	}
	f := os.NewFile(uintptr(fd), "images.json")
	defer f.Close()
	doc, err := readSandboxImageStoreFile(f, a.UID, uint64(before.Dev), before.Ino) //nolint:unconvert // Dev is int32 on darwin
	return doc, true, err
}

func readSandboxImageStoreFile(f *os.File, uid int, dev uint64, ino uint64) (sandboxImageStore, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return sandboxImageStore{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != uid || uint64(st.Dev) != dev || st.Ino != ino {
		return sandboxImageStore{}, errors.New("images.json is not a regular file owned by the account")
	}
	if st.Size > imageStoreMaxBytes {
		return sandboxImageStore{}, errors.New("images.json is too large")
	}
	data, err := io.ReadAll(io.LimitReader(f, imageStoreMaxBytes+1))
	if err != nil {
		return sandboxImageStore{}, err
	}
	if len(data) > imageStoreMaxBytes {
		return sandboxImageStore{}, errors.New("images.json is too large")
	}
	var doc sandboxImageStore
	if err := json.Unmarshal(data, &doc); err != nil || doc.Version != 1 || !sandboxImageOwnerRE.MatchString(doc.Owner) {
		return sandboxImageStore{}, errors.New("images.json has invalid version or no valid 16-hex owner")
	}
	return doc, nil
}

func sandboxImageListCommand(owner string) string {
	return "docker image ls --filter label=" + image.LabelSandboxImage + "=1 --filter label=" + image.LabelOwner + "=" + owner
}

// sandboxDockerReason keeps one bounded Docker error line. A line resembling
// a credential is withheld instead of putting it in an uninstall result.
func sandboxDockerReason(result CommandResult, err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "Docker timed out"
	}
	line := strings.TrimSpace(strings.SplitN(string(result.Stderr), "\n", 2)[0])
	if line == "" {
		if err == nil {
			return "Docker command failed"
		}
		line = strings.TrimSpace(strings.SplitN(err.Error(), "\n", 2)[0])
	}
	line = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, line)
	lower := strings.ToLower(line)
	for _, sensitive := range []string{"token", "secret", "password", "authorization", "bearer", "api_key", "apikey", "@"} {
		if strings.Contains(lower, sensitive) {
			return "Docker command failed (details withheld)"
		}
	}
	if dockerUnixQueryRE.MatchString(lower) || strings.Contains(dockerUnixSocketRE.ReplaceAllString(lower, ""), "://") || dockerAddressRE.MatchString(line) {
		return "Docker command failed (details withheld)"
	}
	if len(line) > 240 {
		line = line[:240]
	}
	return line
}

func (e *Env) runSandboxDocker(ctx context.Context, docker string, args ...string) (CommandResult, error) {
	// ExecRunner may report a killed process as an exit error without its
	// deadline. Keep the outer deadline so the warning can name the timeout.
	runCtx, cancel := context.WithTimeout(ctx, imageRemoveTimeout)
	defer cancel()
	out, err := e.longRunner(imageRemoveTimeout).Run(runCtx, docker, args...)
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return out, context.DeadlineExceeded
	}
	return out, err
}

func sandboxImageRanks(store sandboxImageStore, ranks map[string]int) {
	setRank := func(tag string, rank int) {
		if old, ok := ranks[tag]; !ok || rank < old {
			ranks[tag] = rank
		}
	}
	for _, rec := range store.Images {
		setRank(rec.Tag, 2)
	}
	for _, rec := range store.RunImages {
		if rec.Alias {
			setRank(rec.Tag, 1)
		} else {
			setRank(rec.Tag, 0)
		}
	}
}

func (l *lifecycle) warnSandboxDockerUnavailable(a SandboxAccount, owner string, ranks map[string]int, reason string) {
	listCommand := sandboxImageListCommand(owner)
	var tags []string
	invalid := 0
	for tag := range ranks {
		if sandboxImageRefRE.MatchString(tag) {
			tags = append(tags, tag)
		} else {
			invalid++
		}
	}
	sort.Slice(tags, func(i, j int) bool {
		if ranks[tags[i]] != ranks[tags[j]] {
			return ranks[tags[i]] < ranks[tags[j]]
		}
		return tags[i] < tags[j]
	})
	for _, tag := range tags[:min(len(tags), imageWarningLimit)] {
		l.result.AddWarning(codeSandboxUserState, fmt.Sprintf("left recorded DefenseClaw sandbox image %s of user %s: %s; this image was not verified because Docker could not list it; as root check `%s`, then run `docker image rm %s` if it belongs to this account", tag, a.Name, reason, listCommand, tag))
	}
	message := fmt.Sprintf("could not list the DefenseClaw sandbox images of user %s: %s; as root run `%s`, then remove each listed tag with `docker image rm <tag>`", a.Name, reason, listCommand)
	if invalid > 0 {
		message += fmt.Sprintf("; %d recorded tag(s) were not shown because they are not valid image names", invalid)
	}
	if len(tags) > imageWarningLimit {
		message += fmt.Sprintf("; and %d more recorded tags; use the list command", len(tags)-imageWarningLimit)
	}
	l.result.AddWarning(codeSandboxUserState, message)
}

// purgeAccountSandboxImages removes only this account's labelled Docker
// image tags, after the containers and volumes of its sandboxes in both
// namespaces of the managed gateways (purgeSandboxOwnerContainers), which
// would keep an image in use. Linux's managed Docker is host-wide; on macOS
// Docker Desktop belongs to the account, so the existing account-run
// teardown handles it. Every failure is a warning: the local file purge must
// still finish.
func (l *lifecycle) purgeAccountSandboxImages(ctx context.Context, a SandboxAccount) {
	if l.env.GOOS != "linux" {
		return
	}
	e, r := l.env, l.result
	stores := []struct{ name, rel string }{{"daemon state store", filepath.Join(e.daemonStateRel(), "sandboxes", "images.json")}}
	// Stores written before GAP-0548 (1.0.0 to 1.0.1) remain an upgrade path
	// until those builds are no longer upgraded from. Purge keeps this legacy
	// folder when the account has its own DefenseClaw install (GAP-0490).
	if _, err := os.Lstat(e.P(filepath.Join(a.Home, ".defenseclaw", "config.yaml"))); errors.Is(err, os.ErrNotExist) {
		stores = append(stores, struct{ name, rel string }{"legacy store", filepath.Join(userSandboxDataRel, "images.json")})
	}
	owners := map[string]map[string]int{}
	var ownerOrder []string
	for _, path := range stores {
		store, found, err := e.readSandboxImageStore(a, path.rel)
		if err != nil {
			if found {
				r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not safely read the sandbox image store of user %s (%s): %v; no Docker image was removed for this account from this store", a.Name, path.name, err))
			}
			continue
		}
		if !found {
			continue
		}
		if _, ok := owners[store.Owner]; !ok {
			owners[store.Owner] = map[string]int{}
			ownerOrder = append(ownerOrder, store.Owner)
		}
		sandboxImageRanks(store, owners[store.Owner])
	}
	for _, owner := range ownerOrder {
		l.purgeSandboxOwnerContainers(ctx, a, owner)
		l.purgeSandboxOwnerImages(ctx, a, owner, owners[owner])
	}
}

func (l *lifecycle) purgeSandboxOwnerImages(ctx context.Context, a SandboxAccount, owner string, ranks map[string]int) {
	e, r := l.env, l.result
	listCommand := sandboxImageListCommand(owner)
	docker := e.firstExisting(e.binCandidates("docker"))
	if docker == "" {
		l.warnSandboxDockerUnavailable(a, owner, ranks, "Docker CLI is missing")
		return
	}
	args := []string{"image", "ls", "--filter", "label=" + image.LabelSandboxImage + "=1", "--filter", "label=" + image.LabelOwner + "=" + owner,
		"--no-trunc", "--format", "{{.Repository}}:{{.Tag}}\t{{.ID}}"}
	listed, err := e.runSandboxDocker(ctx, docker, args...)
	if err != nil {
		l.warnSandboxDockerUnavailable(a, owner, ranks, sandboxDockerReason(listed, err))
		return
	}
	var candidates []sandboxDockerImage
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(listed.Stdout)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 || !sandboxImageRefRE.MatchString(parts[0]) || !sandboxImageIDRE.MatchString(parts[1]) {
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not parse a Docker image row for user %s; no image was removed for that row; as root run `%s`", a.Name, listCommand))
			continue
		}
		if seen[parts[0]] {
			continue
		}
		seen[parts[0]] = true
		ref, id := parts[0], parts[1]
		inspected, inspectErr := e.runSandboxDocker(ctx, docker, "image", "inspect", "--format", "{{json .}}", ref)
		if inspectErr != nil {
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("left DefenseClaw sandbox image %s (%s) of user %s: could not inspect it: %s; as root run `docker image rm %s` after checking `%s`", ref, id[7:19], a.Name, sandboxDockerReason(inspected, inspectErr), ref, listCommand))
			continue
		}
		var facts struct {
			ID     string `json:"Id"`
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
		}
		if json.Unmarshal(inspected.Stdout, &facts) != nil || facts.ID != id || facts.Config.Labels[image.LabelSandboxImage] != "1" ||
			facts.Config.Labels[image.LabelOwner] != owner || facts.Config.Labels[image.LabelUID] != strconv.Itoa(a.UID) {
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("left candidate sandbox image %s (%s) of user %s: its image ID, owner or account uid label did not match; check `%s` before removing it", ref, id[7:19], a.Name, listCommand))
			continue
		}
		rank, ok := ranks[ref]
		if !ok {
			rank = 2
		}
		if facts.Config.Labels[image.LabelRunImage] != "" {
			rank = 0
		}
		candidates = append(candidates, sandboxDockerImage{tag: ref, id: id, rank: rank})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].rank != candidates[j].rank {
			return candidates[i].rank < candidates[j].rank
		}
		return candidates[i].tag < candidates[j].tag
	})
	var removed []string
	for _, candidate := range candidates {
		out, err := e.runSandboxDocker(ctx, docker, "image", "rm", candidate.tag)
		if err != nil {
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("left DefenseClaw sandbox image %s (%s) of user %s: %s; as root run `docker image rm %s` (list this account's images with `%s`)", candidate.tag, candidate.id[7:19], a.Name, sandboxDockerReason(out, err), candidate.tag, listCommand))
			continue
		}
		removed = append(removed, candidate.tag)
	}
	if len(removed) > 0 {
		shown := removed
		if len(shown) > imageNameLimit {
			shown = shown[:imageNameLimit]
		}
		line := fmt.Sprintf("removed %d DefenseClaw sandbox images of user %s (%s", len(removed), a.Name, strings.Join(shown, ", "))
		if len(removed) > len(shown) {
			line += fmt.Sprintf(", and %d more", len(removed)-len(shown))
		}
		r.Changes = append(r.Changes, line+")")
	}
}
