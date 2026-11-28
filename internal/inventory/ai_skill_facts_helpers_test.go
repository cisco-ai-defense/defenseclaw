// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

// hashSkillFolder hashes the skill folder at root as a scan outside every
// home does, retaining no manifest.
func hashSkillFolder(root string, limit int64) (hash, status string, consumed int64) {
	hash, status, _, consumed = hashSkillFolderCapture(root, limit, 0)
	return hash, status, consumed
}

// hashSkillFolderCapture also retains a root SKILL.md prefix.
func hashSkillFolderCapture(root string, limit int64, captureLimit int) (hash, status string, manifest []byte, consumed int64) {
	hash, status, manifest, _, consumed, _ = hashSkillFolderCaptureNamed(root, limit, captureLimit, skillHomeOwnerTrust(""), nil)
	return hash, status, manifest, consumed
}
