// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/productlayout"
)

const plantedPathToken = "aB3dE5gH7jK9mN1pQ3sT5uV7"

func redactAuditTarget(t *testing.T, input string) string {
	t.Helper()
	result, err := DetectAndRedact(input, observability.FieldClassContent, DetectorGroups(), make([]byte, hashV1KeySize), NewRecordMatchBudget())
	if err != nil {
		t.Fatalf("DetectAndRedact(%q): %v", input, err)
	}
	return result.Value
}

// Every product folder stays readable in a path target, whatever the path form.
func TestProductFolderNamesStayVisibleInPathTargets(t *testing.T) {
	t.Parallel()
	for _, folder := range productlayout.FolderNames() {
		for _, shape := range []string{
			`C:\ProgramData\Cisco\%s`,
			`C:\ProgramData\Cisco\%s\guardian.exe`,
			`C:\Program Files\Cisco\Cisco Secure Client\%s\1234567890\x.log`,
			`\\?\C:\ProgramData\Cisco\%s\`,
			`"C:\ProgramData\Cisco\%s\run"`,
			`C:/ProgramData/Cisco/%s/x`,
			`/opt/cisco/%s/x`,
			`%s`,
		} {
			input := strings.Replace(shape, "%s", folder, 1)
			if got := redactAuditTarget(t, input); got != input {
				t.Errorf("product folder redacted: %q -> %q", input, got)
			}
		}
	}
}

// Real key material inside a path is still redacted, and the product folder
// next to it stays visible.
func TestPlantedTokenInPathStaysRedactedBesideProductFolder(t *testing.T) {
	t.Parallel()
	folder := productlayout.WindowsHookRuntimeFolder
	for _, input := range []string{
		`C:\ProgramData\Cisco\` + folder + `\` + plantedPathToken,
		`C:\ProgramData\Cisco\` + plantedPathToken + `\` + folder + `\x.log`,
		`C:\ProgramData\Cisco\` + folder + `\` + plantedPathToken + `\x.log`,
		`/var/` + plantedPathToken + `/x`,
		`/var/` + folder + `/` + plantedPathToken,
		`/var/` + plantedPathToken + `/` + folder + `/x`,
		`C:/Users/a/` + plantedPathToken + `/x`,
	} {
		got := redactAuditTarget(t, input)
		if strings.Contains(got, plantedPathToken) {
			t.Errorf("token left in path: %q -> %q", input, got)
		}
		if strings.Contains(input, folder) && !strings.Contains(got, folder) {
			t.Errorf("product folder lost beside a token: %q -> %q", input, got)
		}
	}
}

// A secret that contains or extends a product folder name is not the folder
// name, so it is still redacted.
func TestProductFolderPrefixOrSuffixIsNotAllowed(t *testing.T) {
	t.Parallel()
	folder := productlayout.WindowsHookRuntimeFolder
	for _, name := range []string{folder + "-" + plantedPathToken, plantedPathToken + "-" + folder, folder + "Zk9"} {
		input := `C:\ProgramData\Cisco\` + name
		if got := redactAuditTarget(t, input); got == input {
			t.Errorf("name that extends a product folder was left in clear: %q", input)
		}
	}
}

// A high-entropy value does not become readable because a product folder name
// sits between two pieces of it: the folder is taken out before judging, and
// what remains is judged as one value.
func TestProductFolderBetweenSecretPiecesDoesNotHideTheSecret(t *testing.T) {
	t.Parallel()
	for _, folder := range []string{
		productlayout.ProductFolder,
		strings.ToLower(productlayout.ProductFolder),
		strings.ToUpper(productlayout.ProductFolder),
		productlayout.WindowsHookRuntimeFolder,
	} {
		for _, shape := range []string{
			`aB3dE5gH7jK/%s/mN1pQ3sT5uV`,
			`/aB3dE5gH7jK/%s/mN1pQ3sT5uV`,
			`aB3dE5gH7jK/%s/mN1pQ3sT5uV/%s/xY2zA4bC6dE`,
		} {
			input := strings.ReplaceAll(shape, "%s", folder)
			got := redactAuditTarget(t, input)
			if got == input || strings.Contains(got, "aB3dE5gH7jK") || strings.Contains(got, "mN1pQ3sT5uV") {
				t.Errorf("secret pieces left readable around %q: %q -> %q", folder, input, got)
			}
			if !strings.Contains(got, folder) {
				t.Errorf("product folder lost beside secret pieces: %q -> %q", input, got)
			}
		}
	}
}

// The benign twin: short ordinary components around a product folder name stay
// readable, in every case spelling.
func TestProductFolderBesideOrdinaryComponentsStaysVisible(t *testing.T) {
	t.Parallel()
	for _, folder := range []string{productlayout.ProductFolder, strings.ToLower(productlayout.ProductFolder), productlayout.WindowsHookRuntimeFolder} {
		for _, shape := range []string{`/opt/cisco/%s/x`, `/opt/cisco/%s/logs/%s/x`, `/var/lib/%s`} {
			input := strings.ReplaceAll(shape, "%s", folder)
			if got := redactAuditTarget(t, input); got != input {
				t.Errorf("ordinary path redacted: %q -> %q", input, got)
			}
		}
	}
}
