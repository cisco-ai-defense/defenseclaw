// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// mirrorEnterpriseHookGatewayUnprotectedAgents makes the gateway copy of the
// administrator status record (unprotected-agents.json), next to the guardian
// ledger where the gateway can read it (it cannot read the root-only record).
// A user own status is answered from this copy, so it says what the
// administrator status says about that user (rel-1-0-6 GAP-0789).
//
// The copy is the bytes of the record as it stands after this cycle write,
// with the record scan time, never a second computation: when the record
// could not be replaced the copy keeps speaking for the record the
// administrator still sees, so a copy and a record cannot disagree. When the
// record cannot be read or the copy cannot be written, the previous copy is
// withdrawn (withdrawEnterpriseHookGatewayUnprotectedAgents), so an absent or
// emptied copy is an unknown scan to the gateway, never "nothing found".
func mirrorEnterpriseHookGatewayUnprotectedAgents(dataDir, rootRecordPath string) error {
	path := filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), managed.HookGuardianUnprotectedAgentsFile)
	err := func() error {
		data, scanned, err := enterprisehooks.ReadUnprotectedAgentsRecord(rootRecordPath)
		if err != nil {
			return err
		}
		if _, err := enterprisehooks.ParseUnprotectedAgents(data); err != nil {
			return err
		}
		if err := writeEnterpriseHookGatewayRecord(path, data); err != nil {
			return err
		}
		// The copy is as old as the scan it holds, so a record that was not
		// replaced does not look fresh through its copy.
		return os.Chtimes(path, scanned, scanned)
	}()
	if err == nil {
		return nil
	}
	return errors.Join(err, withdrawEnterpriseHookGatewayUnprotectedAgents(path))
}

// withdrawEnterpriseHookGatewayUnprotectedAgents removes the gateway copy. A
// directory that refuses the removal still lets the file be emptied in place,
// which the gateway reads as an unknown scan; only when neither works does the
// old copy stand (until its age runs out).
func withdrawEnterpriseHookGatewayUnprotectedAgents(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	removeErr := os.Remove(path)
	if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
		return nil
	}
	if !info.Mode().IsRegular() {
		return removeErr
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return errors.Join(removeErr, err)
	}
	return file.Close()
}
