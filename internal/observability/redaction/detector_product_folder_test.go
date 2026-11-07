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
			`C:/ProgramData/Cisco/%s`,
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

// A high-entropy value the detector redacts as written does not become
// readable because a product folder name sits between two pieces of it: the
// folder is taken out before judging, and what remains is judged as one value.
// (A hyphenated folder name such as DefenseClaw-HookRuntime makes the span fail
// the detector alphabet check as written, so a value split by it was never
// redacted and is outside this test.)
func TestProductFolderBetweenSecretPiecesDoesNotHideTheSecret(t *testing.T) {
	t.Parallel()
	for _, folder := range []string{
		productlayout.ProductFolder,
		strings.ToLower(productlayout.ProductFolder),
		strings.ToUpper(productlayout.ProductFolder),
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

// A letter-only high-entropy value split by a product folder component is
// still one value: the detector redacted it before the folder was special, and
// a digit is not what makes a value a key.
func TestProductFolderBetweenLetterOnlyPiecesDoesNotHideTheSecret(t *testing.T) {
	t.Parallel()
	for _, folder := range []string{productlayout.ProductFolder, strings.ToLower(productlayout.ProductFolder), strings.ToUpper(productlayout.ProductFolder)} {
		input := "aBcDeFgHiJkL/" + folder + "/mNoPqRsTuVwX"
		got := redactAuditTarget(t, input)
		if got == input || strings.Contains(got, "aBcDeFgHiJkL") || strings.Contains(got, "mNoPqRsTuVwX") {
			t.Errorf("letter-only pieces left readable around %q: %q -> %q", folder, input, got)
		}
		if !strings.Contains(got, folder) {
			t.Errorf("product folder lost beside letter-only pieces: %q -> %q", input, got)
		}
	}
}

// The benign twin: a path the detector leaves alone as written is not
// redacted because the folder component is taken out and the remainder looks
// denser, whatever the child names (digits or not).
func TestProductFolderBesideDatedOrdinaryChildStaysVisible(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"C:/ProgramData/Cisco/" + productlayout.WindowsHookRuntimeFolder + "/Release2026",
		"/opt/MyService/" + productlayout.WindowsHookRuntimeFolder + "/Reports2026",
	} {
		if got := redactAuditTarget(t, input); got != input {
			t.Errorf("ordinary dated path redacted: %q -> %q", input, got)
		}
	}
}

// The benign twin: an ordinary parent directory in front of a hyphenated
// product folder does not make the prefix a candidate. The detector leaves such
// a slash-form path alone as written, and the folder name is not what changes
// that.
func TestProductFolderBehindOrdinaryParentsStaysVisible(t *testing.T) {
	t.Parallel()
	folder := productlayout.WindowsHookRuntimeFolder
	for _, input := range []string{
		"C:/ProgramData/Cisco/SecureClient/Extra/" + folder,
		"C:/ProgramData/Cisco/SecureClient/" + folder + "/x",
		"/opt/MyService/CurrentRelease/" + folder + "/x",
		"/Users/Example/Library/ApplicationSupport/" + folder,
		"/srv/MyService/CurrentRelease/" + folder + "/Reports2026",
	} {
		if got := redactAuditTarget(t, input); got != input {
			t.Errorf("ordinary parent redacted: %q -> %q", input, got)
		}
	}
}

// A token is still redacted when ordinary parents stand in front of the
// hyphenated product folder, and the folder stays readable.
func TestPlantedTokenBehindOrdinaryParentsStaysRedacted(t *testing.T) {
	t.Parallel()
	folder := productlayout.WindowsHookRuntimeFolder
	for _, input := range []string{
		"/opt/MyService/CurrentRelease/" + plantedPathToken + "/" + folder + "/x",
		"/opt/MyService/CurrentRelease/" + folder + "/" + plantedPathToken,
		"C:/ProgramData/Cisco/SecureClient/" + folder + "/" + plantedPathToken,
	} {
		got := redactAuditTarget(t, input)
		if strings.Contains(got, plantedPathToken) {
			t.Errorf("token left in path: %q -> %q", input, got)
		}
		if !strings.Contains(got, folder) {
			t.Errorf("product folder lost beside a token: %q -> %q", input, got)
		}
	}
}
