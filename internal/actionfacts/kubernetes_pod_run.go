// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"io"
	"path"
	"strings"
)

// ExactKubernetesPodRun returns one exact privileged pod-run fact.
func ExactKubernetesPodRun(facts Facts) (KubernetesPodRunFact, bool) {
	if len(facts.KubernetesPodRuns) != 1 {
		return KubernetesPodRunFact{}, false
	}
	fact := facts.KubernetesPodRuns[0]
	if !fact.Privileged || !validPrivateDigest(fact.PodIdentityDigest) {
		return KubernetesPodRunFact{}, false
	}
	return fact, true
}

func projectKubernetesPodRuns(input Input, facts Facts) []KubernetesPodRunFact {
	argv, schemaNamespace, ok := exactKubectlArgv(input, facts)
	if !ok {
		return nil
	}
	argv, namespace, ok := stripExactKubectlNamespace(argv, schemaNamespace)
	if !ok {
		return nil
	}
	fact, ok := exactPrivilegedKubectlRun(argv, namespace)
	if !ok {
		return nil
	}
	return []KubernetesPodRunFact{fact}
}

func exactKubernetesPodRunInputSchema(raw json.RawMessage) bool {
	command, namespace, ok := exactStructuredKubectlInput(raw)
	if !ok {
		return false
	}
	parsed := parsePOSIX("kubectl "+command, 1, 0)
	projected := parsed.factsWithContext("kubectl", "", "")
	if !projected.Authoritative() || len(projected.Commands) != 1 ||
		!exactDirectKubectlCommand(projected.Commands[0]) {
		return false
	}
	argv, namespace, ok := stripExactKubectlNamespace(projected.Commands[0].Argv, namespace)
	if !ok {
		return false
	}
	_, ok = exactPrivilegedKubectlRun(argv, namespace)
	return ok
}

func exactPrivilegedKubectlRun(argv []string, namespace string) (KubernetesPodRunFact, bool) {
	if len(argv) < 4 || path.Base(argv[0]) != "kubectl" || argv[1] != "run" ||
		!exactKubernetesIdentity(argv[2]) {
		return KubernetesPodRunFact{}, false
	}
	fact := KubernetesPodRunFact{
		PodIdentityDigest: kubernetesPodIdentityDigest(namespace, argv[2]),
	}
	imageSeen := false
	for index := 3; index < len(argv); index++ {
		arg := argv[index]
		if arg == "--" {
			break
		}
		key, value, hasValue := strings.Cut(arg, "=")
		switch key {
		case "--privileged":
			if hasValue && value != "true" {
				return KubernetesPodRunFact{}, false
			}
			fact.Privileged = true
		case "--image":
			if !hasValue {
				index++
				if index >= len(argv) {
					return KubernetesPodRunFact{}, false
				}
				value = argv[index]
			}
			if imageSeen || value == "" || hasUnresolvedPathSyntax(value) {
				return KubernetesPodRunFact{}, false
			}
			imageSeen = true
		case "--overrides":
			if !hasValue {
				index++
				if index >= len(argv) {
					return KubernetesPodRunFact{}, false
				}
				value = argv[index]
			}
			privileged, hostPID, hostNetwork, overrideOK := exactPodRunOverrides(value)
			if !overrideOK {
				return KubernetesPodRunFact{}, false
			}
			fact.Privileged = fact.Privileged || privileged
			fact.HostPID = hostPID
			fact.HostNetwork = hostNetwork
		case "--command", "--attach", "--stdin", "-i", "--tty", "-t", "-it", "-ti", "--quiet", "-q":
			if hasValue {
				return KubernetesPodRunFact{}, false
			}
		case "--restart", "--image-pull-policy", "--env", "--labels", "-l", "--port":
			if !hasValue {
				index++
				if index >= len(argv) {
					return KubernetesPodRunFact{}, false
				}
			}
		case "--dry-run":
			return KubernetesPodRunFact{}, false
		default:
			return KubernetesPodRunFact{}, false
		}
	}
	if !imageSeen || !fact.Privileged {
		return KubernetesPodRunFact{}, false
	}
	return fact, true
}

func exactPodRunOverrides(raw string) (privileged, hostPID, hostNetwork, ok bool) {
	if raw == "" || len(raw) > kubernetesManifestMaxBytes {
		return false, false, false, false
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.UseNumber()
	if decoder.Decode(&document) != nil || len(document) == 0 {
		return false, false, false, false
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return false, false, false, false
	}
	for key := range document {
		if key != "apiVersion" && key != "spec" {
			return false, false, false, false
		}
	}
	if version, present := document["apiVersion"]; present && version != "v1" {
		return false, false, false, false
	}
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return false, false, false, false
	}
	for key, value := range spec {
		switch key {
		case "hostPID":
			hostPID, ok = value.(bool)
			if !ok {
				return false, false, false, false
			}
		case "hostNetwork":
			hostNetwork, ok = value.(bool)
			if !ok {
				return false, false, false, false
			}
		case "containers":
			containers, exact := value.([]any)
			if !exact || len(containers) != 1 {
				return false, false, false, false
			}
			container, exact := containers[0].(map[string]any)
			if !exact {
				return false, false, false, false
			}
			for containerKey, containerValue := range container {
				switch containerKey {
				case "name":
					name, valid := containerValue.(string)
					if !valid || !exactKubernetesDNSLabel(name) {
						return false, false, false, false
					}
				case "image":
					image, valid := containerValue.(string)
					if !valid || image == "" || len(image) > maxScalarBytes ||
						hasUnresolvedPathSyntax(image) {
						return false, false, false, false
					}
				case "command", "args":
					if !exactStaticStringArray(containerValue) {
						return false, false, false, false
					}
				case "securityContext":
					context, valid := containerValue.(map[string]any)
					if !valid || len(context) != 1 {
						return false, false, false, false
					}
					requested, valid := context["privileged"].(bool)
					if !valid {
						return false, false, false, false
					}
					privileged = requested
				case "volumeMounts":
					// A mount is meaningful only together with a closed volumes
					// declaration. Validate their identity linkage below.
				case "stdin", "stdinOnce", "tty":
					if _, valid := containerValue.(bool); !valid {
						return false, false, false, false
					}
				default:
					return false, false, false, false
				}
			}
			if !exactPodRunHostRootLink(spec, container) {
				return false, false, false, false
			}
		case "volumes":
			// Parsed together with the sole container so a nearby hostPath
			// cannot be mistaken for a mounted host root.
		default:
			return false, false, false, false
		}
	}
	return privileged, hostPID, hostNetwork, true
}

func exactStaticStringArray(value any) bool {
	items, ok := value.([]any)
	if !ok || len(items) == 0 || len(items) > 128 {
		return false
	}
	for _, item := range items {
		text, ok := item.(string)
		if !ok || text == "" || len(text) > maxScalarBytes ||
			strings.IndexByte(text, 0) >= 0 || hasUnresolvedPathSyntax(text) {
			return false
		}
	}
	return true
}

func exactPodRunHostRootLink(spec, container map[string]any) bool {
	rawVolumes, hasVolumes := spec["volumes"]
	rawMounts, hasMounts := container["volumeMounts"]
	if !hasVolumes && !hasMounts {
		return true
	}
	if !hasVolumes || !hasMounts {
		return false
	}
	volumes, ok := rawVolumes.([]any)
	if !ok || len(volumes) == 0 || len(volumes) > 128 {
		return false
	}
	rootVolumes := make(map[string]struct{}, len(volumes))
	for _, rawVolume := range volumes {
		volume, valid := rawVolume.(map[string]any)
		if !valid || len(volume) != 2 {
			return false
		}
		name, nameOK := volume["name"].(string)
		hostPath, pathOK := volume["hostPath"].(map[string]any)
		if !nameOK || !exactKubernetesDNSLabel(name) || !pathOK ||
			(len(hostPath) != 1 && len(hostPath) != 2) {
			return false
		}
		root, rootOK := hostPath["path"].(string)
		if !rootOK || root != "/" {
			return false
		}
		if volumeType, present := hostPath["type"]; present {
			text, valid := volumeType.(string)
			if !valid || (text != "" && text != "Directory") {
				return false
			}
		}
		rootVolumes[name] = struct{}{}
	}
	mounts, ok := rawMounts.([]any)
	if !ok || len(mounts) == 0 || len(mounts) > 128 {
		return false
	}
	linked := false
	for _, rawMount := range mounts {
		mount, valid := rawMount.(map[string]any)
		if !valid || len(mount) != 2 {
			return false
		}
		name, nameOK := mount["name"].(string)
		mountPath, pathOK := mount["mountPath"].(string)
		if !nameOK || !exactKubernetesDNSLabel(name) || !pathOK ||
			(mountPath != "/host" && mountPath != "/host-root") {
			return false
		}
		if _, present := rootVolumes[name]; present {
			linked = true
		}
	}
	return linked
}
