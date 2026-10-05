// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
)

const (
	eclipseMaxInstalls = 16
	eclipseMaxBundles  = 2048
)

// eclipsePlatformPrefixes are bundles every Eclipse ships; they are left
// out so the list shows what the user added.
var eclipsePlatformPrefixes = []string{
	"org.eclipse.", "org.osgi.", "org.apache.", "javax.", "jakarta.", "com.sun.",
	"org.w3c.", "org.sat4j.", "org.tukaani.", "org.objectweb.", "com.ibm.icu",
	"org.junit", "org.hamcrest", "org.bouncycastle.", "com.google.", "org.slf4j",
	"ch.qos.", "com.jcraft.", "org.commonmark", "org.jsoup", "org.mortbay.",
	"org.glassfish.", "org.xml.", "net.bytebuddy", "org.opentest4j", "org.apiguardian",
	"bcpg", "bcprov", "org.kxml2", "org.xmlpull", "com.sun.jna", "org.mockito",
}

// scanEclipse reads simpleconfigurator bundles.info files of per-user
// Eclipse installations (best effort: Oomph installs under ~/eclipse and
// p2 user configurations under ~/.eclipse).
func (s *scanner) scanEclipse() {
	const info = "org.eclipse.equinox.simpleconfigurator/bundles.info"
	var candidates []string
	home := s.layout.home
	for _, name := range s.subdirs(filepath.Join(home, ".eclipse"), eclipseMaxInstalls) {
		candidates = append(candidates, filepath.Join(home, ".eclipse", name, "configuration", filepath.FromSlash(info)))
	}
	candidates = append(candidates, filepath.Join(home, "eclipse", "configuration", filepath.FromSlash(info)))
	for _, name := range s.subdirs(filepath.Join(home, "eclipse"), eclipseMaxInstalls) {
		base := filepath.Join(home, "eclipse", name)
		candidates = append(candidates,
			filepath.Join(base, "eclipse", "configuration", filepath.FromSlash(info)),
			filepath.Join(base, "Eclipse.app", "Contents", "Eclipse", "configuration", filepath.FromSlash(info)),
		)
	}
	for _, path := range candidates {
		if !s.isFile(path) {
			continue
		}
		data, ok := s.readFileLimit(path, 4<<20)
		if !ok {
			continue
		}
		inst := Install{Family: FamilyEclipse, Product: "eclipse", Channel: "stable", Root: filepath.Dir(filepath.Dir(path))}
		lines := bufio.NewScanner(bytes.NewReader(data))
		lines.Buffer(make([]byte, 0, 4096), 64<<10)
		for lines.Scan() && len(inst.Plugins) < eclipseMaxBundles {
			line := strings.TrimSpace(lines.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Split(line, ",")
			if len(fields) < 2 || eclipsePlatformBundle(fields[0]) {
				continue
			}
			p := Plugin{ID: clean(fields[0]), Version: clean(fields[1]), Scope: ScopeUser, Enabled: EnabledOn, EnabledSource: SourceBundlesInfo, Path: path}
			if p.ID != "" {
				inst.Plugins = append(inst.Plugins, p)
			}
		}
		s.add(inst)
	}
}

func eclipsePlatformBundle(id string) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, prefix := range eclipsePlatformPrefixes {
		if strings.HasPrefix(id, prefix) {
			return true
		}
	}
	return false
}
