// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"path"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0154: the gateway's create path admits a launcher actor with the same
// attestation check as the controller, so both pods mount the template
// anchors Secret, read-only, at the directory of the path the config reads
// by default (config.DefaultSubstrateTemplateAnchors). The gateway leader
// runs no create path and gets no anchors.
func TestTemplateAnchorsReachTheCreatePath(t *testing.T) {
	helm := helmBinary(t)
	wantDir := path.Dir(config.DefaultSubstrateTemplateAnchors)
	wantFile := path.Base(config.DefaultSubstrateTemplateAnchors)
	for _, c := range chartCases {
		t.Run(c, func(t *testing.T) {
			checkTemplateAnchors(t, renderChart(t, helm, c), wantDir, wantFile, true)
		})
	}
	t.Run("no anchors Secret", func(t *testing.T) {
		checkTemplateAnchors(t, renderChart(t, helm, "default", "--set", "controller.templateAnchorsSecret="), wantDir, wantFile, false)
	})
}

func checkTemplateAnchors(t *testing.T, out []byte, wantDir, wantFile string, want bool) {
	t.Helper()
	found := map[string]bool{}
	for _, o := range decodeObjects(t, out) {
		if o.Kind != "Deployment" {
			continue
		}
		name := o.Metadata["name"].(string)
		pod := dig(o.Spec, "template", "spec")
		secret := ""
		for _, v := range asList(dig(pod, "volumes")) {
			if dig(v, "name") != "template-anchors" {
				continue
			}
			secret, _ = dig(v, "secret", "secretName").(string)
			items := asList(dig(v, "secret", "items"))
			if len(items) != 1 || dig(items[0], "path") != wantFile || dig(items[0], "key") != wantFile {
				t.Errorf("%s: anchors volume items %v, want %s", name, items, wantFile)
			}
			if mode := dig(v, "secret", "defaultMode"); mode != 0o440 && mode != 288 {
				t.Errorf("%s: anchors volume mode %v", name, mode)
			}
		}
		for _, ct := range asList(dig(pod, "containers")) {
			for _, m := range asList(dig(ct, "volumeMounts")) {
				if dig(m, "name") != "template-anchors" {
					continue
				}
				if dig(m, "mountPath") != wantDir || dig(m, "readOnly") != true {
					t.Errorf("%s: anchors mounted at %v readOnly=%v, want %s read-only", name, dig(m, "mountPath"), dig(m, "readOnly"), wantDir)
				}
				if secret == "" {
					t.Errorf("%s: anchors mount without its Secret volume", name)
				}
				found[name] = true
			}
		}
	}
	for _, name := range []string{"defenseclaw-controller", "defenseclaw-gateway"} {
		if found[name] != want {
			t.Errorf("%s mounts the template anchors: %v, want %v", name, found[name], want)
		}
	}
	for name := range found {
		if !strings.HasPrefix(name, "defenseclaw-controller") && name != "defenseclaw-gateway" {
			t.Errorf("%s mounts the admin-only template anchors", name)
		}
	}
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}
