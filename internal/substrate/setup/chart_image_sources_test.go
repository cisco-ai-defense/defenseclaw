// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// chartImageRegistry is where the chart's own images live by default.
const chartImageRegistry = "ghcr.io/cisco-ai-defense/"

// substrate-1:GAP-1071: the chart turned the skill scanner sidecar on by
// default with the image ghcr.io/cisco-ai-defense/defenseclaw-scanner, which
// the kind E2E never built, so its gateway pods sat in ImagePullBackOff.
// Every image a chart render names from the chart's registry must be built
// and published by the release (scripts/release/substrate-images.sh, which
// also pins its digest in the packaged chart, run by the release workflow)
// and built by the kind E2E (test/substrate-e2e/defenseclaw.sh) from the
// same Dockerfile. The default render names no image from anywhere else.
func TestChartDefaultImagesHaveABuildSource(t *testing.T) {
	helm := helmBinary(t)
	root := filepath.Join("..", "..", "..")
	read := func(rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	release := read("scripts/release/substrate-images.sh")
	e2e := read("test/substrate-e2e/defenseclaw.sh")
	workflow := read(".github/workflows/release.yaml")
	if !regexp.MustCompile(`(?m)^\s*scripts/release/substrate-images\.sh .*--push`).MatchString(workflow) {
		t.Fatal("the release workflow does not push the Substrate images with scripts/release/substrate-images.sh")
	}

	names := map[string][]string{} // image name -> the chart cases that render it
	for _, c := range chartCases {
		for _, image := range renderedImages(decodeObjects(t, renderChart(t, helm, c))) {
			if !strings.HasPrefix(image, chartImageRegistry) {
				if c == "default" {
					t.Errorf("the default render names %s, which is not from %s and has no build source here", image, chartImageRegistry)
				}
				continue
			}
			name := strings.TrimPrefix(image, chartImageRegistry)
			name, _, _ = strings.Cut(name, "@")
			name, _, _ = strings.Cut(name, ":")
			if !slices.Contains(names[name], c) {
				names[name] = append(names[name], c)
			}
		}
	}
	// The skill scanner sidecar is off by default until its image is
	// published (GAP-1103), so no case renders it from the chart's registry;
	// the default values with it turned on do, and that image needs a build
	// source too.
	for _, image := range renderedImages(decodeObjects(t, renderChart(t, helm, "default", "--set", "gateway.skillScanner.enabled=true"))) {
		name, ok := strings.CutPrefix(image, chartImageRegistry)
		if !ok {
			continue
		}
		name, _, _ = strings.Cut(name, "@")
		name, _, _ = strings.Cut(name, ":")
		if !slices.Contains(names[name], "default+skillScanner") {
			names[name] = append(names[name], "default+skillScanner")
		}
	}
	if len(names["defenseclaw-gateway"]) == 0 || len(names["defenseclaw-scanner"]) == 0 {
		t.Fatalf("the renders name %v; want at least defenseclaw-gateway and defenseclaw-scanner", names)
	}
	for name, cases := range names {
		m := regexp.MustCompile(`(?m)^\S+=\$\(build ` + regexp.QuoteMeta(name) + ` "\$root/(deploy/images/[^"]+/Dockerfile)"`).FindStringSubmatch(release)
		if m == nil {
			t.Errorf("%s (rendered in %v): scripts/release/substrate-images.sh does not build it", name, cases)
			continue
		}
		dockerfile := m[1]
		if _, err := os.Stat(filepath.Join(root, dockerfile)); err != nil {
			t.Errorf("%s: the release builds it from %s, which does not exist: %v", name, dockerfile, err)
		}
		if !strings.Contains(release, `"$registry/`+name+`"`) {
			t.Errorf("%s: scripts/release/substrate-images.sh does not pin its pushed digest in the packaged chart", name)
		}
		if !strings.Contains(e2e, `"$ROOT/`+dockerfile+`"`) {
			t.Errorf("%s (rendered in %v): the kind E2E (test/substrate-e2e/defenseclaw.sh) does not build it from %s, so its pods cannot pull it", name, cases, dockerfile)
		}
	}
}

// renderedImages is every container image (containers, initContainers) in
// the objects' specs, pod templates and job templates included.
func renderedImages(objs []k8sObject) []string {
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if k == "containers" || k == "initContainers" {
					for _, c := range asList(child) {
						if image, ok := dig(c, "image").(string); ok {
							out = append(out, image)
						}
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	for _, o := range objs {
		walk(o.Spec)
	}
	return out
}

// substrate-1:GAP-1133: the kind E2E turns the skill scanner sidecar on, so
// nothing exercised the chart as shipped. E2E_SKILL_SCANNER=off installs the
// chart without that setting and checks the gateway pod has no scanner
// container. The default render must really be that chart: no scanner image.
func TestKindE2ECoversTheChartDefaultWithTheSkillScannerOff(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	read := func(rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	runner, cases := read("test/substrate-e2e/run.sh"), read("test/substrate-e2e/defenseclaw.sh")
	for _, want := range []string{
		`: "${E2E_SKILL_SCANNER:=on}"`,
	} {
		if !strings.Contains(runner, want) {
			t.Errorf("test/substrate-e2e/run.sh lacks %q", want)
		}
	}
	for _, want := range []string{
		`"$E2E_SKILL_SCANNER" = off`,
		"the default chart runs no skill scanner sidecar",
		`*" skill-scanner "*) fail`,
	} {
		if !strings.Contains(cases, want) {
			t.Errorf("test/substrate-e2e/defenseclaw.sh lacks the default-chart case (%q)", want)
		}
	}
	if !strings.Contains(read(".github/workflows/substrate-kind-e2e.yml"), "E2E_SKILL_SCANNER: ${{ inputs.skill_scanner || 'on' }}") {
		t.Error("the Substrate Kind E2E workflow does not pass E2E_SKILL_SCANNER through")
	}
	t.Run("default render", func(t *testing.T) {
		helm := helmBinary(t)
		for _, image := range renderedImages(decodeObjects(t, renderChart(t, helm, "default"))) {
			if strings.Contains(image, "defenseclaw-scanner") {
				t.Fatalf("the default render runs the skill scanner image %s: the E2E default-chart case would not be the default", image)
			}
		}
	})
}
