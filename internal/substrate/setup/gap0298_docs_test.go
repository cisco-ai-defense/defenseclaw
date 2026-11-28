// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// docsAndChartFile reads a file of the repository from this package.
func docsAndChartFile(t *testing.T, rel ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{"..", "..", ".."}, rel...)...))
	if err != nil {
		t.Skipf("the repository tree is not part of this test bundle: %v", err)
	}
	// GAP-1088: a Windows checkout may hold the files with CRLF line ends,
	// and the line patterns here end in $.
	return strings.ReplaceAll(string(raw), "\r\n", "\n")
}

// GAP-0298: reference.mdx tells a user which Deployment to restart after a
// direct edit of a setting that waits for a restart. The controller keeps
// the identity, services, API, llm_providers and bundle settings it started
// with, so its Deployment is one of them, under the name the chart gives it.
func TestGAP0298ReferenceNamesTheControllerRestart(t *testing.T) {
	controller := regexp.MustCompile(`(?m)^  name: (defenseclaw-controller)$`).FindStringSubmatch(
		docsAndChartFile(t, "deploy", "helm", "defenseclaw-substrate", "templates", "controller.yaml"))
	if controller == nil {
		t.Fatal("the chart's controller Deployment is not named defenseclaw-controller")
	}
	doc := docsAndChartFile(t, "docs-site", "content", "docs", "substrate", "reference.mdx")
	start := strings.Index(doc, "After a direct edit of a setting that waits for a restart")
	if start < 0 {
		t.Fatal("reference.mdx lost the restart sentence")
	}
	sentence, _, _ := strings.Cut(doc[start:], "\n\n")
	for _, deployment := range []string{"defenseclaw-gateway", "defenseclaw-gateway-leader", controller[1]} {
		if !strings.Contains(sentence, "deploy/"+deployment) {
			t.Errorf("the restart sentence does not name deploy/%s: %s", deployment, sentence)
		}
	}
}

// GAP-0667: the README's recovery commands for a refused rollback carry the
// release namespace, as the refusal's own text does.
func TestGAP0667ReadmeRollbackCommandsNameTheNamespace(t *testing.T) {
	readme := docsAndChartFile(t, "deploy", "helm", "defenseclaw-substrate", "README.md")
	for _, command := range []string{"helm -n NAMESPACE rollback RELEASE N", "helm -n NAMESPACE history RELEASE"} {
		if !strings.Contains(readme, command) {
			t.Errorf("README lacks %q", command)
		}
	}
	if strings.Contains(readme, "`helm rollback RELEASE N`") || strings.Contains(readme, "`helm history RELEASE`") {
		t.Error("README names a helm rollback or history command with no namespace")
	}
}
