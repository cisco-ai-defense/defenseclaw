// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
	"time"
)

const (
	CredentialFileUploadStrong          = "strong_credential_file"
	CredentialFileUploadKubeAdminConfig = "kubernetes_admin_config"
)

// ExactCredentialFileUploads returns a defensive copy of value-free facts.
func ExactCredentialFileUploads(facts Facts) []CredentialFileUploadFact {
	return append([]CredentialFileUploadFact(nil), facts.CredentialFileUploads...)
}

func projectCredentialFileUploads(facts Facts) []CredentialFileUploadFact {
	if !facts.Authoritative() {
		return nil
	}
	seen := make(map[CredentialFileUploadFact]struct{})
	result := make([]CredentialFileUploadFact, 0, 1)
	for _, command := range facts.Commands {
		if command.Dialect != DialectPOSIX || command.Effect != EffectExecute ||
			command.ControlFlowUncertain {
			continue
		}
		// Every upload client the projection reads counts, by the same
		// closed shapes: a project .env is a credentials file whichever
		// option sends it (GAP-0768, GAP-0770).
		sources := uploadedFileSources(facts, command)
		for _, source := range sources {
			class := credentialFileUploadClass(source)
			if class == "" {
				class = credentialFileBroadClass(source)
			}
			if class == "" {
				continue
			}
			fact := CredentialFileUploadFact{CommandID: command.ID, Class: class}
			if _, duplicate := seen[fact]; duplicate {
				continue
			}
			seen[fact] = struct{}{}
			result = append(result, fact)
		}
	}
	return result
}

// uploadedFileSources is the local files a projected upload sends. curl names
// them by its option table (the TLS and config files it reads are not sent);
// any other upload client sends the files it reads: the local operands of
// scp and rsync, the --post-file or --body-file of wget (GAP-0595).
func uploadedFileSources(facts Facts, command CommandFact) []string {
	if isCurlProgram(command.Program) {
		var sources []string
		for _, source := range StaticCurlDirectUploadFileSources(command) {
			sources = append(sources, source.Path)
		}
		return sources
	}
	return uploadedReadPaths(facts, command)
}

// uploadedReadPaths is the read paths of a command that has an upload
// network fact: none for a command that does not upload.
func uploadedReadPaths(facts Facts, command CommandFact) []string {
	if !hasFactOperation(command, OperationUpload) {
		return nil
	}
	upload := false
	for _, network := range facts.Network {
		if network.CommandID == command.ID && network.Action == NetworkUpload {
			upload = true
			break
		}
	}
	if !upload {
		return nil
	}
	var paths []string
	for _, candidate := range facts.Paths {
		if candidate.CommandID != command.ID || candidate.Access != PathAccessRead {
			continue
		}
		value := candidate.Resolved
		if value == "" {
			value = candidate.Value
		}
		paths = append(paths, value)
	}
	return paths
}

// credentialFileBroadClass is the strong class for a file of any
// credentials-file shape (templates and public keys excluded). A relative
// name is judged by its shape, rooted at /: the hook path often has no
// working directory.
func credentialFileBroadClass(value string) string {
	if value == "" || len(value) > 4096 || strings.ContainsRune(value, 0) ||
		hasUnresolvedPathSyntax(value) {
		return ""
	}
	if !strings.HasPrefix(value, "/") {
		value = path.Join("/", value)
	}
	if _, ok := MatchCredentialFileShape(value); ok {
		return CredentialFileUploadStrong
	}
	return ""
}

func credentialFileUploadClass(value string) string {
	if value == "" || !strings.HasPrefix(value, "/") || hasUnresolvedPathSyntax(value) {
		return ""
	}
	canonical := strings.ToLower(path.Clean(value))
	base := path.Base(canonical)
	if shape, ok := MatchCredentialFileShape(canonical); ok && shape.StrongUpload {
		return CredentialFileUploadStrong
	}
	if base == "jenkins.cookies" || base == "sa.token" ||
		canonical == "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		return CredentialFileUploadStrong
	}
	if hiddenTemporaryCredentialStagingPath(canonical) &&
		(base == "admin.conf" || stagedCredentialArchiveBasename(base)) {
		// These names are credential-bearing only when staged below a hidden
		// directory in an ephemeral filesystem. Keep ordinary backups and the
		// canonical Kubernetes admin config in their weaker class.
		return CredentialFileUploadStrong
	}
	if base == "admin.conf" {
		return CredentialFileUploadKubeAdminConfig
	}
	return ""
}

func hiddenTemporaryCredentialStagingPath(canonical string) bool {
	relative := ""
	for _, root := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		if strings.HasPrefix(canonical, root) {
			relative = strings.TrimPrefix(canonical, root)
			break
		}
	}
	if relative == "" {
		return false
	}
	separator := strings.IndexByte(relative, '/')
	return separator > 1 && relative[0] == '.' &&
		separator < len(relative)-1
}

func stagedCredentialArchiveBasename(base string) bool {
	if strings.HasSuffix(base, ".enc") {
		base = strings.TrimSuffix(base, ".enc")
	}
	if !strings.HasSuffix(base, ".tgz") {
		return false
	}
	stem := strings.TrimSuffix(base, ".tgz")
	prefix := ""
	for _, candidate := range []string{"creds-", "ssh-", "vpn-", "cloud-keys-"} {
		if strings.HasPrefix(stem, candidate) {
			prefix = candidate
			break
		}
	}
	if prefix == "" {
		return false
	}
	date := strings.TrimPrefix(stem, prefix)
	if len(date) != 8 {
		return false
	}
	for _, digit := range date {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	_, err := time.Parse("20060102", date)
	return err == nil
}
