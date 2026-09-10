// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"strconv"
	"strings"
)

const kubernetesCronJobDomain = "defenseclaw/actionfacts/kubernetes-cronjob/v1"

var kubernetesCronJobJSONPatchPath = regexp.MustCompile(
	`^/spec/jobTemplate/spec/template/spec/containers/([0-9]+)/` +
		`(securityContext|volumeMounts)$`,
)

var kubernetesDNSLabelPattern = regexp.MustCompile(
	`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`,
)

// ExactKubernetesCronJobOperation returns one value-free exact operation.
func ExactKubernetesCronJobOperation(
	facts Facts,
) (KubernetesCronJobOperationFact, bool) {
	if len(facts.KubernetesCronJobOperations) != 1 {
		return KubernetesCronJobOperationFact{}, false
	}
	fact := facts.KubernetesCronJobOperations[0]
	if !validPrivateDigest(fact.CronJobIdentityDigest) {
		return KubernetesCronJobOperationFact{}, false
	}
	switch fact.Operation {
	case KubernetesCronJobPrivilegedPatch:
	case KubernetesCronJobCreateFrom, KubernetesCronJobPatchBarrier:
		if fact.HostRoot {
			return KubernetesCronJobOperationFact{}, false
		}
	default:
		return KubernetesCronJobOperationFact{}, false
	}
	return fact, true
}

func projectKubernetesCronJobOperations(
	input Input,
	_ Facts,
) []KubernetesCronJobOperationFact {
	if strings.ToLower(input.Tool) != "kubectl" {
		return nil
	}
	argv, namespace, ok := exactStructuredKubernetesCronJobArgv(input)
	if !ok {
		return nil
	}
	if name, privileged, hostRoot, patchOK := exactKubernetesCronJobPatch(argv); patchOK {
		operation := KubernetesCronJobPatchBarrier
		if privileged {
			operation = KubernetesCronJobPrivilegedPatch
		}
		return []KubernetesCronJobOperationFact{{
			Operation:             operation,
			CronJobIdentityDigest: kubernetesCronJobIdentityDigest(namespace, name),
			HostRoot:              hostRoot,
		}}
	}
	if name, createOK := exactKubernetesCronJobCreate(argv); createOK {
		return []KubernetesCronJobOperationFact{{
			Operation:             KubernetesCronJobCreateFrom,
			CronJobIdentityDigest: kubernetesCronJobIdentityDigest(namespace, name),
		}}
	}
	return nil
}

func exactKubernetesCronJobInputSchema(raw json.RawMessage) bool {
	input := Input{Tool: "kubectl", Args: raw}
	argv, _, ok := exactStructuredKubernetesCronJobArgv(input)
	if !ok {
		return false
	}
	if _, _, _, patchOK := exactKubernetesCronJobPatch(argv); patchOK {
		return true
	}
	_, createOK := exactKubernetesCronJobCreate(argv)
	return createOK
}

func exactStructuredKubernetesCronJobArgv(input Input) ([]string, string, bool) {
	command, schemaNamespace, ok := exactStructuredKubectlInput(input.Args)
	if !ok {
		return nil, "", false
	}
	parsed := parsePOSIX("kubectl "+command, 1, 0)
	projected := parsed.factsWithContext("kubectl", input.CWD, input.ActiveHome)
	if !projected.Authoritative() || len(projected.Commands) != 1 ||
		!exactDirectKubectlCommand(projected.Commands[0]) {
		return nil, "", false
	}
	argv, namespace, ok := stripKubernetesCronJobNamespaces(
		projected.Commands[0].Argv,
		schemaNamespace,
	)
	if !ok {
		return nil, "", false
	}
	if namespace == "" {
		namespace = "default"
	}
	return argv, namespace, true
}

func stripKubernetesCronJobNamespaces(
	argv []string,
	schemaNamespace string,
) ([]string, string, bool) {
	if len(argv) < 2 || path.Base(argv[0]) != "kubectl" ||
		(schemaNamespace != "" && !exactKubernetesNamespace(schemaNamespace)) {
		return nil, "", false
	}
	cleaned := []string{argv[0]}
	namespace := schemaNamespace
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		value := ""
		switch {
		case argument == "-n" || argument == "--namespace":
			if index+1 >= len(argv) {
				return nil, "", false
			}
			index++
			value = argv[index]
		case strings.HasPrefix(argument, "--namespace="):
			value = strings.TrimPrefix(argument, "--namespace=")
		default:
			cleaned = append(cleaned, argument)
			continue
		}
		if !exactKubernetesNamespace(value) || namespace != "" && namespace != value {
			return nil, "", false
		}
		namespace = value
	}
	return cleaned, namespace, true
}

func exactKubernetesCronJobPatch(argv []string) (string, bool, bool, bool) {
	if len(argv) < 6 || path.Base(argv[0]) != "kubectl" || argv[1] != "patch" ||
		argv[2] != "cronjob" || !exactKubernetesCronJobName(argv[3]) {
		return "", false, false, false
	}
	patchType := "strategic"
	patchTypeSeen := false
	payload := ""
	for index := 4; index < len(argv); index++ {
		argument := argv[index]
		switch {
		case argument == "-p" || argument == "--patch":
			if payload != "" || index+1 >= len(argv) {
				return "", false, false, false
			}
			index++
			payload = argv[index]
		case strings.HasPrefix(argument, "--patch="):
			if payload != "" {
				return "", false, false, false
			}
			payload = strings.TrimPrefix(argument, "--patch=")
		case strings.HasPrefix(argument, "-p="):
			if payload != "" {
				return "", false, false, false
			}
			payload = strings.TrimPrefix(argument, "-p=")
		case argument == "--type":
			if patchTypeSeen || index+1 >= len(argv) {
				return "", false, false, false
			}
			index++
			patchType = strings.ToLower(argv[index])
			patchTypeSeen = true
		case strings.HasPrefix(argument, "--type="):
			if patchTypeSeen {
				return "", false, false, false
			}
			patchType = strings.ToLower(strings.TrimPrefix(argument, "--type="))
			patchTypeSeen = true
		default:
			return "", false, false, false
		}
	}
	if payload == "" || len(payload) > kubernetesManifestMaxBytes ||
		validateJSONWithStringLimit([]byte(payload), kubernetesManifestMaxBytes) != "" {
		return "", false, false, false
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewBufferString(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return "", false, false, false
	}
	var privileged, hostRoot bool
	switch patchType {
	case "json":
		privileged, hostRoot = exactKubernetesCronJobJSONPatch(decoded)
	case "strategic", "merge":
		privileged, hostRoot = exactKubernetesCronJobMergePatch(decoded)
	default:
		return "", false, false, false
	}
	return argv[3], privileged, hostRoot, true
}

func exactKubernetesCronJobCreate(argv []string) (string, bool) {
	if len(argv) != 5 || path.Base(argv[0]) != "kubectl" ||
		argv[1] != "create" || argv[2] != "job" {
		return "", false
	}
	jobName := ""
	cronJobName := ""
	for _, argument := range argv[3:] {
		if strings.HasPrefix(argument, "--from=cronjob/") {
			if cronJobName != "" {
				return "", false
			}
			cronJobName = strings.TrimPrefix(argument, "--from=cronjob/")
			continue
		}
		if strings.HasPrefix(argument, "-") || jobName != "" {
			return "", false
		}
		jobName = argument
	}
	return cronJobName, exactKubernetesCronJobName(cronJobName) &&
		exactKubernetesJobName(jobName)
}

func exactKubernetesCronJobJSONPatch(value any) (bool, bool) {
	operations, ok := value.([]any)
	if !ok || len(operations) == 0 || len(operations) > 16 {
		return false, false
	}
	privilegedContainer := -1
	rootVolumes := map[string]struct{}{}
	mountedRoots := map[int]map[string]struct{}{}
	hostFieldsSeen := false
	for _, rawOperation := range operations {
		operation, objectOK := rawOperation.(map[string]any)
		if !objectOK || len(operation) != 3 {
			return false, false
		}
		op, opOK := operation["op"].(string)
		pointer, pathOK := operation["path"].(string)
		patchValue, valueOK := operation["value"]
		if !opOK || !pathOK || !valueOK || (op != "add" && op != "replace") {
			return false, false
		}
		for key := range operation {
			if key != "op" && key != "path" && key != "value" {
				return false, false
			}
		}
		if pointer == "/spec/jobTemplate/spec/template/spec/volumes" {
			hostFieldsSeen = true
			volumes, exact := exactKubernetesHostRootVolumes(patchValue)
			if !exact {
				return false, false
			}
			for name := range volumes {
				rootVolumes[name] = struct{}{}
			}
			continue
		}
		matches := kubernetesCronJobJSONPatchPath.FindStringSubmatch(pointer)
		if len(matches) != 3 {
			return false, false
		}
		containerIndex, err := strconv.Atoi(matches[1])
		if err != nil || containerIndex < 0 || containerIndex > 127 ||
			strconv.Itoa(containerIndex) != matches[1] {
			return false, false
		}
		switch matches[2] {
		case "securityContext":
			context, contextOK := patchValue.(map[string]any)
			privileged, privilegedOK := context["privileged"].(bool)
			if !contextOK || len(context) != 1 || !privilegedOK || !privileged ||
				privilegedContainer != -1 && privilegedContainer != containerIndex {
				return false, false
			}
			privilegedContainer = containerIndex
		case "volumeMounts":
			hostFieldsSeen = true
			mounts, exact := exactKubernetesRootMounts(patchValue)
			if !exact {
				return false, false
			}
			mountedRoots[containerIndex] = mounts
		}
	}
	if privilegedContainer < 0 {
		return false, false
	}
	hostRoot := linkedKubernetesHostRoot(
		rootVolumes,
		mountedRoots[privilegedContainer],
	)
	return !hostFieldsSeen || hostRoot, hostRoot
}

func exactKubernetesCronJobMergePatch(value any) (bool, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return false, false
	}
	spec, ok := exactNestedJSONObject(
		root, "spec", "jobTemplate", "spec", "template", "spec",
	)
	if !ok {
		return false, false
	}
	containers, ok := spec["containers"].([]any)
	if !ok || len(containers) == 0 || len(containers) > 128 {
		return false, false
	}
	rootVolumes := map[string]struct{}{}
	hostFieldsSeen := false
	if rawVolumes, present := spec["volumes"]; present {
		hostFieldsSeen = true
		var exact bool
		rootVolumes, exact = exactKubernetesHostRootVolumes(rawVolumes)
		if !exact {
			return false, false
		}
	}
	privilegedSeen := false
	hostRoot := false
	for _, rawContainer := range containers {
		container, objectOK := rawContainer.(map[string]any)
		if !objectOK {
			return false, false
		}
		if name, present := container["name"]; present {
			text, nameOK := name.(string)
			if !nameOK || !exactKubernetesDNSLabel(text) {
				return false, false
			}
		}
		securityContext, hasContext := container["securityContext"].(map[string]any)
		privileged, isBool := securityContext["privileged"].(bool)
		if !hasContext || !isBool || !privileged {
			if _, mentionsPrivilege := securityContext["privileged"]; mentionsPrivilege {
				return false, false
			}
			continue
		}
		privilegedSeen = true
		if rawMounts, present := container["volumeMounts"]; present {
			hostFieldsSeen = true
			mounts, exact := exactKubernetesRootMounts(rawMounts)
			if !exact {
				return false, false
			}
			hostRoot = hostRoot || linkedKubernetesHostRoot(rootVolumes, mounts)
		}
	}
	return privilegedSeen && (!hostFieldsSeen || hostRoot), hostRoot
}

func exactNestedJSONObject(root map[string]any, keys ...string) (map[string]any, bool) {
	current := root
	for _, key := range keys {
		next, ok := current[key].(map[string]any)
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func exactKubernetesHostRootVolumes(value any) (map[string]struct{}, bool) {
	items, ok := value.([]any)
	if !ok || len(items) == 0 || len(items) > 128 {
		return nil, false
	}
	result := make(map[string]struct{})
	for _, rawItem := range items {
		item, objectOK := rawItem.(map[string]any)
		name, nameOK := item["name"].(string)
		hostPath, hostPathOK := item["hostPath"].(map[string]any)
		root, rootOK := hostPath["path"].(string)
		if !objectOK || !nameOK || !hostPathOK || !rootOK ||
			!exactKubernetesDNSLabel(name) {
			return nil, false
		}
		if root == "/" {
			result[name] = struct{}{}
		}
	}
	return result, true
}

func exactKubernetesRootMounts(value any) (map[string]struct{}, bool) {
	items, ok := value.([]any)
	if !ok || len(items) == 0 || len(items) > 128 {
		return nil, false
	}
	result := make(map[string]struct{})
	for _, rawItem := range items {
		item, objectOK := rawItem.(map[string]any)
		name, nameOK := item["name"].(string)
		mountPath, mountPathOK := item["mountPath"].(string)
		if !objectOK || !nameOK || !mountPathOK ||
			!exactKubernetesDNSLabel(name) {
			return nil, false
		}
		if mountPath == "/host" || mountPath == "/host-root" {
			result[name] = struct{}{}
		}
	}
	return result, true
}

func linkedKubernetesHostRoot(
	volumes map[string]struct{},
	mounts map[string]struct{},
) bool {
	for name := range mounts {
		if _, ok := volumes[name]; ok {
			return true
		}
	}
	return false
}

func kubernetesCronJobIdentityDigest(namespace, name string) string {
	if !exactKubernetesNamespace(namespace) || !exactKubernetesCronJobName(name) {
		return ""
	}
	return framedPrivateDigest(kubernetesCronJobDomain, namespace, name)
}

func exactKubernetesNamespace(value string) bool {
	return exactKubernetesDNSLabel(value)
}

func exactKubernetesDNSLabel(value string) bool {
	return len(value) <= 63 && kubernetesDNSLabelPattern.MatchString(value)
}

func exactKubernetesCronJobName(value string) bool {
	// CronJob controllers append an 11-character suffix to child Job names;
	// Kubernetes therefore limits CronJob names to 52 characters.
	return len(value) <= 52 && exactKubernetesIdentity(value)
}

func exactKubernetesJobName(value string) bool {
	return len(value) <= 63 && exactKubernetesIdentity(value)
}
