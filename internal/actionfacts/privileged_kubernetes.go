// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	kubernetesManifestMaxBytes  = 64 << 10
	kubernetesIdentityMaxScalar = 253
	kubernetesArtifactDomain    = "defenseclaw/actionfacts/kubernetes-manifest-path/v1"
	kubernetesPodDomain         = "defenseclaw/actionfacts/kubernetes-pod/v1"
)

var kubernetesDNSNamePattern = regexp.MustCompile(
	`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`,
)

// ExactPrivilegedKubernetesOperation returns one value-free, exact operation.
func ExactPrivilegedKubernetesOperation(
	facts Facts,
) (PrivilegedKubernetesOperationFact, bool) {
	if len(facts.PrivilegedKubernetesOperations) != 1 {
		return PrivilegedKubernetesOperationFact{}, false
	}
	fact := facts.PrivilegedKubernetesOperations[0]
	switch fact.Operation {
	case KubernetesPrivilegedManifestWrite:
		if !validPrivateDigest(fact.ArtifactIdentityDigest) ||
			!validPrivateDigest(fact.PodIdentityDigest) {
			return PrivilegedKubernetesOperationFact{}, false
		}
	case KubernetesManifestApply:
		if !validPrivateDigest(fact.ArtifactIdentityDigest) ||
			fact.PodIdentityDigest != "" {
			return PrivilegedKubernetesOperationFact{}, false
		}
	case KubernetesPodHostPathExec:
		if fact.ArtifactIdentityDigest != "" ||
			!validPrivateDigest(fact.PodIdentityDigest) {
			return PrivilegedKubernetesOperationFact{}, false
		}
	default:
		return PrivilegedKubernetesOperationFact{}, false
	}
	return fact, true
}

// ExactSingleArtifactMutationDigest returns one exact normalized path digest
// when the action may mutate precisely one non-device artifact. It returns no
// identity for ambiguous multi-path mutation.
func ExactSingleArtifactMutationDigest(facts Facts) (string, bool) {
	selected := ""
	for _, candidate := range facts.Paths {
		switch candidate.Access {
		case PathAccessWrite, PathAccessAppend, PathAccessDelete:
		default:
			continue
		}
		if candidate.Flavor != PathFlavorPOSIX || candidate.Resolved == "" ||
			hasUnresolvedPathSyntax(candidate.Value) {
			return "", false
		}
		digest := kubernetesArtifactIdentityDigest(candidate.Resolved)
		if digest == "" {
			return "", false
		}
		if selected != "" && selected != digest {
			return "", false
		}
		selected = digest
	}
	return selected, selected != ""
}

func projectPrivilegedKubernetesOperations(
	input Input,
	facts Facts,
) []PrivilegedKubernetesOperationFact {
	if artifact, manifest, ok := exactKubernetesManifestWrite(input, facts); ok {
		name, namespace, manifestOK := exactPrivilegedPodManifest(manifest)
		if manifestOK {
			return []PrivilegedKubernetesOperationFact{{
				Operation:              KubernetesPrivilegedManifestWrite,
				ArtifactIdentityDigest: kubernetesArtifactIdentityDigest(artifact),
				PodIdentityDigest:      kubernetesPodIdentityDigest(namespace, name),
			}}
		}
	}
	argv, schemaNamespace, ok := exactKubectlArgv(input, facts)
	if !ok {
		return nil
	}
	cleaned, namespace, ok := stripExactKubectlNamespace(argv, schemaNamespace)
	if !ok {
		return nil
	}
	if artifact, applyOK := exactKubectlApply(cleaned); applyOK && namespace == "" {
		resolved, pathOK := exactNormalizedPOSIXPath(artifact, input.CWD, input.ActiveHome)
		if !pathOK {
			return nil
		}
		return []PrivilegedKubernetesOperationFact{{
			Operation:              KubernetesManifestApply,
			ArtifactIdentityDigest: kubernetesArtifactIdentityDigest(resolved),
		}}
	}
	if pod, execOK := exactKubectlHostPathExec(cleaned); execOK {
		return []PrivilegedKubernetesOperationFact{{
			Operation:         KubernetesPodHostPathExec,
			PodIdentityDigest: kubernetesPodIdentityDigest(namespace, pod),
		}}
	}
	return nil
}

func exactKubernetesManifestWrite(input Input, facts Facts) (string, string, bool) {
	switch strings.ToLower(input.Tool) {
	case "write_file", "file_write":
		artifact, content, ok := exactStructuredManifestWrite(input)
		if !ok || !facts.Authoritative() {
			return "", "", false
		}
		resolved, ok := exactNormalizedPOSIXPath(artifact, input.CWD, input.ActiveHome)
		return resolved, content, ok
	}
	return "", "", false
}

func exactStructuredManifestWrite(input Input) (string, string, bool) {
	if len(input.Args) == 0 || len(input.Args) > maxArgsJSONBytes || !utf8.Valid(input.Args) ||
		validateJSONWithStringLimit(input.Args, kubernetesManifestMaxBytes) != "" {
		return "", "", false
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(input.Args))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || len(object) != 2 {
		return "", "", false
	}
	artifact, pathOK := object["path"].(string)
	content, contentOK := object["content"].(string)
	if !pathOK || !contentOK || artifact == "" || content == "" ||
		len(artifact) > maxScalarBytes || len(content) > kubernetesManifestMaxBytes ||
		strings.TrimSpace(artifact) != artifact || strings.IndexByte(artifact, 0) >= 0 {
		return "", "", false
	}
	for key := range object {
		if key != "path" && key != "content" {
			return "", "", false
		}
	}
	return artifact, content, true
}

type closedPodManifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string            `yaml:"name"`
		Namespace string            `yaml:"namespace,omitempty"`
		Labels    map[string]string `yaml:"labels,omitempty"`
	} `yaml:"metadata"`
	Spec struct {
		Containers []struct {
			Name            string   `yaml:"name"`
			Image           string   `yaml:"image,omitempty"`
			Command         []string `yaml:"command,omitempty"`
			Args            []string `yaml:"args,omitempty"`
			SecurityContext struct {
				Privileged *bool `yaml:"privileged,omitempty"`
			} `yaml:"securityContext,omitempty"`
			VolumeMounts []struct {
				Name      string `yaml:"name"`
				MountPath string `yaml:"mountPath"`
			} `yaml:"volumeMounts,omitempty"`
		} `yaml:"containers"`
		Volumes []struct {
			Name     string `yaml:"name"`
			HostPath *struct {
				Path string `yaml:"path"`
				Type string `yaml:"type,omitempty"`
			} `yaml:"hostPath,omitempty"`
		} `yaml:"volumes"`
		RestartPolicy string `yaml:"restartPolicy,omitempty"`
		HostNetwork   bool   `yaml:"hostNetwork,omitempty"`
		HostPID       bool   `yaml:"hostPID,omitempty"`
	} `yaml:"spec"`
}

func exactPrivilegedPodManifest(source string) (name, namespace string, ok bool) {
	if source == "" || len(source) > kubernetesManifestMaxBytes || !utf8.ValidString(source) {
		return "", "", false
	}
	nodeDecoder := yaml.NewDecoder(strings.NewReader(source))
	var document yaml.Node
	if err := nodeDecoder.Decode(&document); err != nil ||
		!closedKubernetesYAMLNode(&document, 0, new(int)) {
		return "", "", false
	}
	var extraNode yaml.Node
	if err := nodeDecoder.Decode(&extraNode); err != io.EOF {
		return "", "", false
	}
	decoder := yaml.NewDecoder(strings.NewReader(source))
	decoder.KnownFields(true)
	var manifest closedPodManifest
	if err := decoder.Decode(&manifest); err != nil {
		return "", "", false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return "", "", false
	}
	if manifest.APIVersion != "v1" || manifest.Kind != "Pod" ||
		!exactKubernetesIdentity(manifest.Metadata.Name) ||
		(manifest.Metadata.Namespace != "" && !exactKubernetesIdentity(manifest.Metadata.Namespace)) {
		return "", "", false
	}
	hostRootVolumes := make(map[string]struct{}, len(manifest.Spec.Volumes))
	for _, volume := range manifest.Spec.Volumes {
		if volume.HostPath != nil && volume.HostPath.Path == "/" &&
			exactKubernetesIdentity(volume.Name) {
			hostRootVolumes[volume.Name] = struct{}{}
		}
	}
	for _, container := range manifest.Spec.Containers {
		if container.SecurityContext.Privileged == nil ||
			!*container.SecurityContext.Privileged {
			continue
		}
		for _, mount := range container.VolumeMounts {
			if mount.MountPath != "/host" && mount.MountPath != "/host-root" {
				continue
			}
			if _, hostRoot := hostRootVolumes[mount.Name]; hostRoot {
				return manifest.Metadata.Name, manifest.Metadata.Namespace, true
			}
		}
	}
	return "", "", false
}

func closedKubernetesYAMLNode(node *yaml.Node, depth int, count *int) bool {
	if node == nil || count == nil || depth > 32 {
		return false
	}
	(*count)++
	if *count > 1024 || node.Kind == yaml.AliasNode || node.Anchor != "" {
		return false
	}
	switch node.Tag {
	case "", "!!map", "!!seq", "!!str", "!!bool", "!!null":
	default:
		return false
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			if index+1 >= len(node.Content) || node.Content[index].Value == "<<" {
				return false
			}
		}
	}
	for _, child := range node.Content {
		if !closedKubernetesYAMLNode(child, depth+1, count) {
			return false
		}
	}
	return true
}

func exactKubectlArgv(input Input, facts Facts) ([]string, string, bool) {
	if strings.ToLower(input.Tool) == "kubectl" {
		command, namespace, ok := exactStructuredKubectlInput(input.Args)
		if !ok {
			return nil, "", false
		}
		parsed := parsePOSIX("kubectl "+command, 1, 0)
		projected := parsed.factsWithContext("kubectl", input.CWD, input.ActiveHome)
		if !projected.Authoritative() || len(projected.Commands) != 1 ||
			!exactDirectKubectlCommand(projected.Commands[0]) {
			return nil, "", false
		}
		return cloneSlice(projected.Commands[0].Argv), namespace, true
	}
	if len(facts.Commands) != 1 || !exactDirectKubectlCommand(facts.Commands[0]) {
		return nil, "", false
	}
	return cloneSlice(facts.Commands[0].Argv), "", true
}

func exactStructuredKubectlInput(raw json.RawMessage) (string, string, bool) {
	if len(raw) == 0 || len(raw) > maxArgsJSONBytes || !utf8.Valid(raw) ||
		validateJSONWithStringLimit(raw, maxCommandBytes) != "" {
		return "", "", false
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || (len(object) != 1 && len(object) != 2) {
		return "", "", false
	}
	command, commandOK := object["command"].(string)
	if !commandOK || validateCommandText(command) != "" || strings.TrimSpace(command) != command {
		return "", "", false
	}
	namespace := ""
	for key, value := range object {
		switch key {
		case "command":
		case "namespace":
			var namespaceOK bool
			namespace, namespaceOK = value.(string)
			if !namespaceOK || !exactKubernetesIdentity(namespace) {
				return "", "", false
			}
		default:
			return "", "", false
		}
	}
	return command, namespace, true
}

func exactDirectKubectlCommand(command CommandFact) bool {
	return command.Effect == EffectExecute && command.Program == "kubectl" &&
		command.ParentCommandID == 0 && command.PipelineID == 0 &&
		!command.ControlFlowUncertain && command.ArgvComplete &&
		len(command.Wrappers) == 0 && len(command.Redirects) == 0 &&
		(command.Dialect == DialectPOSIX || command.Dialect == DialectArgv)
}

func stripExactKubectlNamespace(argv []string, schema string) ([]string, string, bool) {
	if len(argv) < 2 || path.Base(argv[0]) != "kubectl" {
		return nil, "", false
	}
	cleaned := []string{argv[0]}
	namespace := schema
	namespaceSeen := schema != ""
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		if arg == "--" {
			cleaned = append(cleaned, argv[index:]...)
			break
		}
		value := ""
		switch {
		case arg == "-n" || arg == "--namespace":
			if index+1 >= len(argv) {
				return nil, "", false
			}
			index++
			value = argv[index]
		case strings.HasPrefix(arg, "--namespace="):
			value = strings.TrimPrefix(arg, "--namespace=")
		default:
			cleaned = append(cleaned, arg)
			continue
		}
		if !exactKubernetesIdentity(value) || namespaceSeen {
			return nil, "", false
		}
		namespace = value
		namespaceSeen = true
	}
	return cleaned, namespace, true
}

func exactKubectlApply(argv []string) (string, bool) {
	if len(argv) != 4 || path.Base(argv[0]) != "kubectl" || argv[1] != "apply" ||
		(argv[2] != "-f" && argv[2] != "--filename") {
		return "", false
	}
	return argv[3], argv[3] != "" && argv[3] != "-"
}

func exactKubectlHostPathExec(argv []string) (string, bool) {
	if len(argv) < 6 || path.Base(argv[0]) != "kubectl" || argv[1] != "exec" {
		return "", false
	}
	index := 2
	for index < len(argv) {
		switch argv[index] {
		case "-i", "-t", "-it", "-ti":
			index++
		default:
			goto pod
		}
	}
pod:
	if index >= len(argv) || !exactKubernetesIdentity(argv[index]) {
		return "", false
	}
	podName := argv[index]
	index++
	if index >= len(argv) || argv[index] != "--" || index+2 >= len(argv) {
		return "", false
	}
	payload := argv[index+1:]
	for payloadIndex, argument := range payload {
		name := path.Base(argument)
		switch name {
		case "sh", "bash", "zsh", "dash", "ksh", "mksh", "fish",
			"python", "python2", "python3", "perl", "ruby", "node":
			return "", false
		}
		if payloadIndex == 0 {
			switch name {
			case "busybox", "env", "command", "exec", "sudo", "xargs":
				return "", false
			}
		}
	}
	hostPath := false
	for _, argument := range payload[1:] {
		if argument == "/host" || argument == "/host-root" {
			hostPath = true
		}
	}
	return podName, hostPath
}

func exactNormalizedPOSIXPath(value, cwd, activeHome string) (string, bool) {
	if value == "" || len(value) > maxScalarBytes || strings.TrimSpace(value) != value ||
		pathFlavor(value) != PathFlavorPOSIX || hasUnresolvedPathSyntax(value) {
		return "", false
	}
	paths := []PathFact{{Access: PathAccessWrite, Flavor: PathFlavorPOSIX, Value: value}}
	normalizePathFacts(paths, cwd, activeHome)
	return paths[0].Resolved, paths[0].Resolved != "" && paths[0].Flavor == PathFlavorPOSIX
}

func exactKubernetesIdentity(value string) bool {
	return value != "" && len(value) <= kubernetesIdentityMaxScalar &&
		strings.ToLower(value) == value && kubernetesDNSNamePattern.MatchString(value) &&
		!strings.Contains(value, "..")
}

func kubernetesArtifactIdentityDigest(resolved string) string {
	if resolved == "" || !strings.HasPrefix(resolved, "/") {
		return ""
	}
	return framedPrivateDigest(kubernetesArtifactDomain, resolved)
}

func kubernetesPodIdentityDigest(namespace, name string) string {
	if !exactKubernetesIdentity(name) || namespace != "" && !exactKubernetesIdentity(namespace) {
		return ""
	}
	return framedPrivateDigest(kubernetesPodDomain, namespace, name)
}

func framedPrivateDigest(values ...string) string {
	hash := sha256.New()
	var length [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validPrivateDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
