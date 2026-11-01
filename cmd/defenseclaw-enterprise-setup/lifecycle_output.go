// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// maximumLifecycleOutput bounds what Setup republishes from one lifecycle
// stream. The lifecycle's JSON result is the last thing it prints, so a
// longer stream keeps its tail rather than failing a lifecycle that already
// succeeded.
const maximumLifecycleOutput = 2 << 20

// boundedLifecycleTail returns at most limit bytes from the end of output,
// starting at a line boundary when the cut falls inside a line, and reports
// whether anything was dropped.
func boundedLifecycleTail(output []byte, limit int) ([]byte, bool) {
	if limit <= 0 || len(output) <= limit {
		return output, false
	}
	tail := output[len(output)-limit:]
	if newline := bytes.IndexByte(tail, '\n'); newline >= 0 && newline < len(tail)-1 {
		tail = tail[newline+1:]
	}
	return tail, true
}

// stagingBlockedPrereq renders the error Setup reports when every staging
// parent refused a new protected directory with access denied: Controlled
// Folder Access or an endpoint product blocking the Setup executable. The
// text is the resilience-event line itself so log scrapers and the JSON
// error read the same thing.
func stagingBlockedPrereq(setupPath string, parents []string, cause error) string {
	if strings.TrimSpace(setupPath) == "" {
		setupPath = enterpriseSetupArtifactName
	}
	fields := map[string]string{
		"check": "staging_directory",
		"path":  strings.Join(parents, ";"),
		"reason": "access denied creating the protected staging directory; Controlled Folder Access " +
			"or an endpoint protection product is blocking " + enterpriseSetupArtifactName,
		"remedy": "allow " + setupPath + " through Controlled Folder Access (Windows Security > Virus & threat " +
			"protection > Ransomware protection > Allow an app through Controlled folder access, or " +
			"Add-MpPreference -ControlledFolderAccessAllowedApplications '" + setupPath + "') and in the " +
			"endpoint protection allow list, then run Setup again",
	}
	if cause != nil {
		fields["error"] = cause.Error()
	}
	return managed.FormatResilienceEvent(managed.MarkerPrereq, fields)
}
