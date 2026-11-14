// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package workspace

import "github.com/defenseclaw/defenseclaw/internal/scanner"

// The copy rules of this package for callers that move files themselves
// on any operating system (the Agent Substrate launcher's host copy, which
// works on Windows; GAP-0173). They are the same rules Stage and Pull apply,
// exposed without the OpenShell sandbox and platform checks; OpenShell
// sandboxes still run on Linux and macOS only.

// HeldBack reports whether rel (a slash-separated path in the project)
// stays on this computer when the folder is copied: a secret directory, a
// built-in secret name or an operator mask, unless an --unmask exception
// keeps it visible. content, when not nil, returns the file's content for
// the secret detector (det; nil skips the content check); its result is
// used only for regular files the caller already checked.
func HeldBack(rel string, masks, unmask []string, content func() ([]byte, bool), det SecretDetector) (rule string, held bool) {
	if unmaskedBy(unmask, rel) {
		return "", false
	}
	if secretByName(masks, rel) {
		return "secret name", true
	}
	if det == nil || content == nil {
		return "", false
	}
	b, ok := content()
	if !ok || len(b) == 0 || len(b) > maxContentScanBytes || looksBinary(b) {
		return "", false
	}
	return det.DetectSecret(rel, b)
}

// UnderHeavyDir reports whether rel is inside a package cache or tool
// state directory (node_modules, .venv, ...) that a copy skips.
func UnderHeavyDir(rel string) bool { return underHeavyDir(rel) }

// ReviewFlags flags the changes that can run code on this machine, as a
// pull review does. content returns a file's content before (after false)
// or after the change.
func ReviewFlags(changes []TreeChange, content func(c TreeChange, after bool) ([]byte, bool), sensitive []string) []Flag {
	return classifyChanges(changes, content, sensitive)
}

// SecretFinding is a critical secret the detector found in a changed file,
// in the form a pull review reports it.
func SecretFinding(path, rule string) ScanFinding {
	return ScanFinding{Path: path, Scanner: "clawshield-secrets", RuleID: rule, Severity: string(scanner.SeverityCritical), Title: "contains what looks like a secret"}
}
