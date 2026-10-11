// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// A managed Windows gateway reads the skill and plugin folders of enrolled
// users but cannot delete in them: the enumerator grants its service account
// read and execute only. The LocalSystem hook guardian completes such a
// quarantine on the gateway's request (GAP-0202, owner decision 2026-10-07):
// the gateway copies the source into quarantine and verifies the copy, then
// writes a request; the guardian checks that the source lies inside an
// enrolled user's watched folder and that the source and the quarantine copy
// both carry the planned hash, removes the source as that user, and answers.

const (
	quarantineRemovalVersion  = 1
	quarantineRemovalMaxBytes = 16 << 10
	quarantineRemovalPoll     = 250 * time.Millisecond
)

// QuarantineRemovalRequest is one request file the gateway writes.
type QuarantineRemovalRequest struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Nonce   string `json:"nonce"`
	// Kind is QuarantineRequestReadGrant for a read grant; empty is a
	// removal.
	Kind           string `json:"kind,omitempty"`
	TargetType     string `json:"target_type"`
	SourcePath     string `json:"source_path"`
	QuarantinePath string `json:"quarantine_path"`
	ContentHash    string `json:"content_hash"`
	// Deferred says, in a deferred request, why the guardian waits.
	Deferred string `json:"deferred,omitempty"`
}

// QuarantineRequestReadGrant asks the guardian to let the gateway read a
// skill or plugin folder of an enrolled user. A folder moved into a watched
// folder keeps the access control list it had where it came from, which has
// no entry for the gateway service: its scan and its quarantine copy failed
// with access denied and the asset stayed in place (GAP-0825).
const QuarantineRequestReadGrant = "read-grant"

// QuarantineRequestRemoveLink asks the guardian to remove a skill or plugin
// that is a link (a symlink or junction) directly in an enrolled user's
// watched folder. The link entry is deleted; the folder it points to is
// never opened (GAP-1188).
const QuarantineRequestRemoveLink = "remove-link"

// QuarantineRemovalResult is the guardian's answer to one request.
type QuarantineRemovalResult struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Nonce   string `json:"nonce"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// QuarantineRemovalChannel is where the gateway writes requests (a folder only
// it and administrators can write) and where the guardian answers (a folder
// only the guardian can write and the gateway can read).
//
// DeferredDir, also guardian-only, keeps the requests the guardian finishes
// later.
type QuarantineRemovalChannel struct {
	RequestDir  string
	ResultDir   string
	DeferredDir string
}

// QuarantineRemovalChannelFor is the channel of a gateway data directory and
// its hook guardian authorization directory.
func QuarantineRemovalChannelFor(dataDir, guardianAuthDir string) QuarantineRemovalChannel {
	return QuarantineRemovalChannel{
		RequestDir:  filepath.Join(dataDir, "guardian-requests", "quarantine"),
		ResultDir:   filepath.Join(guardianAuthDir, "quarantine-results"),
		DeferredDir: filepath.Join(guardianAuthDir, "quarantine-deferred"),
	}
}

// ErrQuarantineRemovalDeferred marks a removal the guardian cannot do yet:
// the user who owns the folder is signed out and Windows gives no S4U logon
// for the account (a Microsoft Entra ID account has none). The source stayed
// in the profile with only an error in the log (GAP-0414); the guardian now
// keeps the request and removes the folder when that user next signs in.
var ErrQuarantineRemovalDeferred = errors.New("removal deferred until the user signs in")

var quarantineSourceRemover atomic.Pointer[func(AssetQuarantinePlan, string) error]

// SetQuarantineSourceRemover installs what removes a quarantined source this
// process may not delete itself; nil removes it.
func SetQuarantineSourceRemover(remove func(plan AssetQuarantinePlan, recordID string) error) {
	if remove == nil {
		quarantineSourceRemover.Store(nil)
		return
	}
	quarantineSourceRemover.Store(&remove)
}

// removeQuarantinedSource removes the verified source of a quarantine, and
// hands a source this process may not delete to the installed remover.
func removeQuarantinedSource(plan AssetQuarantinePlan, recordID string) error {
	err := removeAssetPath(plan.SourcePath, plan.SourceRoot)
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	remove := quarantineSourceRemover.Load()
	if remove == nil {
		return err
	}
	if delegated := (*remove)(plan, recordID); delegated != nil {
		return fmt.Errorf("%w; hook guardian: %w", err, delegated)
	}
	return nil
}

// Remover asks the guardian over c and waits up to timeout for its answer.
func (c QuarantineRemovalChannel) Remover(timeout time.Duration) func(AssetQuarantinePlan, string) error {
	return func(plan AssetQuarantinePlan, recordID string) error {
		return c.request(plan, recordID, timeout)
	}
}

// ReadGranter asks the guardian over c to let the gateway read the asset at
// path, and waits up to timeout for its answer.
func (c QuarantineRemovalChannel) ReadGranter(timeout time.Duration) func(targetType, path string) error {
	return func(targetType, path string) error {
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return err
		}
		return c.publish(QuarantineRemovalRequest{
			ID: "read-" + hex.EncodeToString(id), Kind: QuarantineRequestReadGrant,
			TargetType: targetType, SourcePath: path,
		}, timeout)
	}
}

// LinkRemover asks the guardian over c to remove the linked asset at path,
// and waits up to timeout for its answer.
func (c QuarantineRemovalChannel) LinkRemover(timeout time.Duration) func(targetType, path string) error {
	return func(targetType, path string) error {
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return err
		}
		return c.publish(QuarantineRemovalRequest{
			ID: "link-" + hex.EncodeToString(id), Kind: QuarantineRequestRemoveLink,
			TargetType: targetType, SourcePath: path,
		}, timeout)
	}
}

func (c QuarantineRemovalChannel) request(plan AssetQuarantinePlan, recordID string, timeout time.Duration) error {
	if !safePathSegment(recordID) {
		return fmt.Errorf("invalid quarantine journal id")
	}
	return c.publish(QuarantineRemovalRequest{
		ID: recordID, TargetType: plan.TargetType, SourcePath: plan.SourcePath,
		QuarantinePath: plan.QuarantinePath, ContentHash: plan.ContentHash,
	}, timeout)
}

// publish writes request (with a fresh nonce) for the guardian and waits up
// to timeout for its answer.
func (c QuarantineRemovalChannel) publish(request QuarantineRemovalRequest, timeout time.Duration) error {
	recordID := request.ID
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	request.Version, request.Nonce = quarantineRemovalVersion, hex.EncodeToString(nonce)
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.RequestDir, 0o700); err != nil {
		return fmt.Errorf("create request folder: %w", err)
	}
	path := filepath.Join(c.RequestDir, recordID+".json")
	stage := path + ".tmp"
	if err := os.WriteFile(stage, payload, 0o600); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	if err := os.Rename(stage, path); err != nil {
		_ = os.Remove(stage)
		return fmt.Errorf("publish request: %w", err)
	}
	defer os.Remove(path)
	resultPath := filepath.Join(c.ResultDir, recordID+".json")
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(quarantineRemovalPoll) {
		var result QuarantineRemovalResult
		if readQuarantineRemovalFile(resultPath, &result) != nil || result.Nonce != request.Nonce || result.ID != recordID {
			continue
		}
		if result.OK {
			return nil
		}
		answer := strings.TrimSpace(result.Error)
		if rest, deferred := strings.CutPrefix(answer, ErrQuarantineRemovalDeferred.Error()); deferred {
			return fmt.Errorf("%w%s", ErrQuarantineRemovalDeferred, rest)
		}
		return errors.New(answer)
	}
	return fmt.Errorf("no answer within %s (is the DefenseClawHookGuardian service running?)", timeout)
}

// ServeOnce answers every pending request with handle and removes the answers
// of requests the gateway has collected. The guardian calls it in a loop.
func (c QuarantineRemovalChannel) ServeOnce(handle func(QuarantineRemovalRequest) error) {
	entries, err := os.ReadDir(c.RequestDir)
	if err != nil {
		return
	}
	pending := map[string]bool{}
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !entry.Type().IsRegular() || !safePathSegment(id) {
			continue
		}
		pending[id] = true
		var request QuarantineRemovalRequest
		if readQuarantineRemovalFile(filepath.Join(c.RequestDir, entry.Name()), &request) != nil || request.ID != id {
			continue
		}
		resultPath := filepath.Join(c.ResultDir, id+".json")
		var previous QuarantineRemovalResult
		if readQuarantineRemovalFile(resultPath, &previous) == nil && previous.Nonce == request.Nonce {
			continue
		}
		result := QuarantineRemovalResult{Version: quarantineRemovalVersion, ID: id, Nonce: request.Nonce, OK: true}
		if err := handle(request); err != nil {
			result.OK, result.Error = false, err.Error()
			if errors.Is(err, ErrQuarantineRemovalDeferred) {
				request.Deferred = strings.TrimPrefix(strings.TrimPrefix(err.Error(), ErrQuarantineRemovalDeferred.Error()), ": ")
				c.deferRequest(request)
			}
		}
		if payload, err := json.Marshal(result); err == nil {
			if os.MkdirAll(c.ResultDir, 0o750) == nil && os.WriteFile(resultPath+".tmp", payload, 0o640) == nil {
				_ = os.Rename(resultPath+".tmp", resultPath)
			}
		}
	}
	results, err := os.ReadDir(c.ResultDir)
	if err != nil {
		return
	}
	for _, entry := range results {
		if id, ok := strings.CutSuffix(entry.Name(), ".json"); ok && !pending[id] {
			_ = os.Remove(filepath.Join(c.ResultDir, entry.Name()))
		}
	}
}

// deferRequest keeps request for ServeDeferred.
func (c QuarantineRemovalChannel) deferRequest(request QuarantineRemovalRequest) {
	if c.DeferredDir == "" || !safePathSegment(request.ID) {
		return
	}
	payload, err := json.Marshal(request)
	if err != nil || os.MkdirAll(c.DeferredDir, 0o700) != nil {
		return
	}
	path := filepath.Join(c.DeferredDir, request.ID+".json")
	if os.WriteFile(path+".tmp", payload, 0o600) == nil {
		_ = os.Rename(path+".tmp", path)
	}
}

// DeferredRemovals lists the removals the guardian waits to do, each with
// why (enterprise windows status reports them, GAP-0795).
func (c QuarantineRemovalChannel) DeferredRemovals() []QuarantineRemovalRequest {
	entries, err := os.ReadDir(c.DeferredDir)
	if err != nil {
		return nil
	}
	var out []QuarantineRemovalRequest
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		var request QuarantineRemovalRequest
		if ok && entry.Type().IsRegular() && safePathSegment(id) &&
			readQuarantineRemovalFile(filepath.Join(c.DeferredDir, entry.Name()), &request) == nil && request.ID == id {
			out = append(out, request)
		}
	}
	return out
}

// ServeDeferred retries every deferred request with handle. A request is
// dropped only after handle removes the source. A transient failure keeps the
// request so a later guardian pass can retry it; every pass verifies the
// enrolled source and quarantine copy again before removal.
func (c QuarantineRemovalChannel) ServeDeferred(handle func(QuarantineRemovalRequest) error) {
	if c.DeferredDir == "" {
		return
	}
	entries, err := os.ReadDir(c.DeferredDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !entry.Type().IsRegular() || !safePathSegment(id) {
			continue
		}
		path := filepath.Join(c.DeferredDir, entry.Name())
		var request QuarantineRemovalRequest
		if readQuarantineRemovalFile(path, &request) != nil || request.ID != id {
			_ = os.Remove(path)
			continue
		}
		if err := handle(request); err == nil {
			_ = os.Remove(path)
		}
	}
}

func readQuarantineRemovalFile(path string, out any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > quarantineRemovalMaxBytes {
		return fmt.Errorf("not a request file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, quarantineRemovalMaxBytes+1))
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, out)
}

var linkedAssetRemover atomic.Pointer[func(targetType, path string) error]

// SetLinkedAssetRemover installs what removes a linked asset this process
// may not delete itself (the hook guardian on a managed Windows computer);
// nil removes it.
func SetLinkedAssetRemover(remove func(targetType, path string) error) {
	if remove == nil {
		linkedAssetRemover.Store(nil)
		return
	}
	linkedAssetRemover.Store(&remove)
}

// VerifyLinkRemoval is the guardian's check of a link removal request: a
// link or reparse point directly in one of sourceRoots (an enrolled user's
// watched folder), reached without a link. It returns the link and the root
// that holds it. A link already gone verifies (the removal is a no-op).
func VerifyLinkRemoval(request QuarantineRemovalRequest, sourceRoots []string) (string, string, error) {
	if request.Version != quarantineRemovalVersion || request.Kind != QuarantineRequestRemoveLink || !safePathSegment(request.ID) {
		return "", "", fmt.Errorf("unsupported link removal request")
	}
	if _, err := quarantineTypeDir(request.TargetType); err != nil {
		return "", "", err
	}
	source, root, err := pathWithinRoots(request.SourcePath, sourceRoots, false)
	if err != nil {
		return "", "", fmt.Errorf("the link is not in an enrolled user's watched folder: %w", err)
	}
	if filepath.Dir(source) != root {
		return "", "", fmt.Errorf("the link %s is not directly in a watched folder", source)
	}
	if request.TargetType == "skill" && IsBundledSkillPath(source) {
		return "", "", ErrBundledSkill
	}
	if err := validateExistingAncestors(root); err != nil {
		return "", "", fmt.Errorf("link ancestry: %w", err)
	}
	info, err := os.Lstat(source)
	if errors.Is(err, fs.ErrNotExist) {
		return source, root, nil
	}
	if err != nil {
		return "", "", fmt.Errorf("inspect link %s: %w", source, err)
	}
	if !fileInfoIsLinkOrReparse(info) {
		return "", "", fmt.Errorf("%s is not a link", source)
	}
	return source, root, nil
}

var assetReadGranter atomic.Pointer[func(targetType, path string) error]

// SetAssetReadGranter installs what lets this process read an asset folder
// it may not read (the hook guardian on a managed Windows computer); nil
// removes it.
func SetAssetReadGranter(grant func(targetType, path string) error) {
	if grant == nil {
		assetReadGranter.Store(nil)
		return
	}
	assetReadGranter.Store(&grant)
}

// ErrNoAssetReadGranter is GrantAssetRead with no granter installed.
var ErrNoAssetReadGranter = errors.New("no read grant is available here")

// GrantAssetRead asks the installed granter to let this process read path.
func GrantAssetRead(targetType, path string) error {
	grant := assetReadGranter.Load()
	if grant == nil {
		return ErrNoAssetReadGranter
	}
	return (*grant)(targetType, path)
}

// VerifyAssetReadGrant is the guardian's check of a read grant request: a
// skill or plugin folder inside one of sourceRoots (an enrolled user's
// watched folder) reached without a link. It returns the folder and the
// root that holds it.
func VerifyAssetReadGrant(request QuarantineRemovalRequest, sourceRoots []string) (string, string, error) {
	if request.Version != quarantineRemovalVersion || request.Kind != QuarantineRequestReadGrant || !safePathSegment(request.ID) {
		return "", "", fmt.Errorf("unsupported read grant request")
	}
	if _, err := quarantineTypeDir(request.TargetType); err != nil {
		return "", "", err
	}
	source, sourceRoot, err := pathWithinRoots(request.SourcePath, sourceRoots, false)
	if err != nil {
		return "", "", fmt.Errorf("the folder is not in an enrolled user's watched folder: %w", err)
	}
	if err := validateContainedAncestors(source, sourceRoot); err != nil {
		return "", "", fmt.Errorf("folder ancestry: %w", err)
	}
	return source, sourceRoot, nil
}

// VerifyProjectSkillRootReadGrant is the guardian's check of a read grant
// for a project skill folder itself, which a hook registers for the watcher
// (GAP-1356): a skill request that names root, which is reached from home,
// the enrolled user's profile, without a link. It returns the folder.
func VerifyProjectSkillRootReadGrant(request QuarantineRemovalRequest, root, home string) (string, error) {
	if request.Version != quarantineRemovalVersion || request.Kind != QuarantineRequestReadGrant ||
		!safePathSegment(request.ID) || request.TargetType != "skill" {
		return "", fmt.Errorf("unsupported read grant request")
	}
	source, _, err := pathWithinRoots(request.SourcePath, []string{root}, true)
	if err != nil || !pathWithin(root, source, true) {
		return "", fmt.Errorf("the folder is not the project skill folder %s", root)
	}
	if err := ValidateLinkFreeRoot(root, home); err != nil {
		return "", err
	}
	return root, nil
}

// ValidateLinkFreeRoot checks that root and every folder between it and
// home, the enrolled user's profile, is reached without a link: a project
// skill folder counts only inside that user's own tree (GAP-1297).
func ValidateLinkFreeRoot(root, home string) error {
	if err := validateContainedAncestors(root, home); err != nil {
		return fmt.Errorf("folder ancestry: %w", err)
	}
	return nil
}

// VerifyQuarantineRemoval is the guardian's check of one request: the source
// is inside one of sourceRoots (an enrolled user's watched folder), the copy
// is inside quarantineRoot, both carry the same name, and both still hash to
// the planned content. It returns the source and the root that holds it. A
// source that is already gone verifies (the removal is then a no-op).
func VerifyQuarantineRemoval(request QuarantineRemovalRequest, sourceRoots []string, quarantineRoot string) (string, string, error) {
	if request.Version != quarantineRemovalVersion || !safePathSegment(request.ID) {
		return "", "", fmt.Errorf("unsupported quarantine removal request")
	}
	if _, err := quarantineTypeDir(request.TargetType); err != nil {
		return "", "", err
	}
	// Win32 drops a final dot or space of an ordinary path, so the guardian
	// would hash and remove the folder of the shorter name: such a name comes
	// only in the extended form the gateway sends (GAP-1007).
	if runtime.GOOS == "windows" && !strings.HasPrefix(request.SourcePath, `\\?\`) &&
		(strings.HasSuffix(request.SourcePath, ".") || strings.HasSuffix(request.SourcePath, " ")) {
		return "", "", fmt.Errorf("the source name ends with a dot or a space, but the path is not in the extended form")
	}
	source, sourceRoot, err := pathWithinRoots(request.SourcePath, sourceRoots, false)
	if err != nil {
		return "", "", fmt.Errorf("source is not in an enrolled user's watched folder: %w", err)
	}
	copyPath, copyRoot, err := pathWithinRoots(request.QuarantinePath, []string{quarantineRoot}, false)
	if err != nil {
		return "", "", fmt.Errorf("copy is not in quarantine storage: %w", err)
	}
	if exactAssetBase(source) != exactAssetBase(copyPath) {
		return "", "", fmt.Errorf("source and copy names differ")
	}
	if request.TargetType == "skill" && IsBundledSkillPath(source) {
		return "", "", ErrBundledSkill
	}
	hash := strings.ToLower(strings.TrimSpace(request.ContentHash))
	if err := validateSHA256Hex(hash); err != nil {
		return "", "", err
	}
	if err := validateContainedAncestors(filepath.Dir(copyPath), copyRoot); err != nil {
		return "", "", fmt.Errorf("quarantine copy ancestry: %w", err)
	}
	if err := requireAssetHash(copyPath, hash); err != nil {
		return "", "", fmt.Errorf("quarantine copy: %w", err)
	}
	if exists, err := assetPathExists(source); err != nil || !exists {
		return source, sourceRoot, err
	}
	if err := validateContainedAncestors(filepath.Dir(source), sourceRoot); err != nil {
		return "", "", fmt.Errorf("source ancestry: %w", err)
	}
	if err := requireAssetHash(source, hash); err != nil {
		return "", "", fmt.Errorf("source changed: %w", err)
	}
	return source, sourceRoot, nil
}
