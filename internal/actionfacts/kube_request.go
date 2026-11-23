// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// The Kubernetes API path decomposition below (kubeAPIPath, kubeVerbFromMethod,
// kubeMetaPath, the special-verb and namespace-subresource tables and the
// apiserver boolean reading) is adapted from denoland/clawpatrol (MIT,
// commit 0e6674c, internal/config/plugins/facets/k8s/k8s.go). See
// THIRD_PARTY_LICENSES.txt.

package actionfacts

import (
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/awkprog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// KubeRequestSource is how a Kubernetes API request was issued.
type KubeRequestSource string

const (
	// KubeSourceKubectl is a kubectl invocation (argv or the structured
	// kubectl tool), including kubectl get --raw.
	KubeSourceKubectl KubeRequestSource = "kubectl"
	// KubeSourceHTTP is a curl or wget request to a Kubernetes apiserver
	// (direct, through kubectl proxy, or with the in-cluster service account).
	KubeSourceHTTP KubeRequestSource = "http"
)

// Kubernetes request verbs (the apiserver's own vocabulary, plus meta for
// discovery and health URIs and proxy for kubectl proxy itself).
const (
	KubeVerbGet    = "get"
	KubeVerbList   = "list"
	KubeVerbWatch  = "watch"
	KubeVerbCreate = "create"
	KubeVerbUpdate = "update"
	KubeVerbPatch  = "patch"
	KubeVerbDelete = "delete"
	KubeVerbProxy  = "proxy"
	KubeVerbMeta   = "meta"
)

// maxKubeRequests bounds the Kubernetes requests one call projects (the
// semantic f.kube bound).
const maxKubeRequests = 32

// KubeRequestFact is one Kubernetes API request as the apiserver would see
// it: verb, group/version/resource/subresource, namespace, name and the
// request parameters that change what it returns or runs (GAP-1824).
// Unknown marks a request that reaches an apiserver but cannot be decomposed
// into that tuple; readers treat it as matching (fail closed), never as
// absent.
type KubeRequestFact struct {
	CommandID      int64
	Source         KubeRequestSource
	Verb           string
	Group          string
	Version        string
	Resource       string
	Subresource    string
	Namespace      string
	Name           string
	AllNamespaces  bool
	Stdin          bool
	TTY            bool
	Command        bool
	LabelSelector  bool
	RevealsContent bool
	Unknown        bool
}

// KubernetesSecretContentRequest reports a request that returns Secret
// content: a get, list or watch of secrets over the apiserver API, a kubectl
// read whose output prints the object (json, yaml, a data selector), a
// kubectl edit of a Secret, or an apiserver request that cannot be
// decomposed (fail closed).
func KubernetesSecretContentRequest(facts Facts) bool {
	for _, request := range facts.KubeRequests {
		if kubeSecretContentRequest(request, true) {
			return true
		}
	}
	return false
}

// KubernetesKnownSecretContentRequest is KubernetesSecretContentRequest for a
// request the action itself names as a Secret read: its resource resolves to
// secrets from the action's own spelling (R-NAME). A request that cannot be
// decomposed (a kind named by a file, a dynamic resource) is no Secret read
// for a blocking rule; only the alert-only rule fails closed on it (DET111
// T20 review P2-2).
func KubernetesKnownSecretContentRequest(facts Facts) bool {
	for _, request := range facts.KubeRequests {
		if kubeSecretContentRequest(request, false) {
			return true
		}
	}
	return false
}

// kubeSecretContentRequest reports one request that returns Secret content;
// with failClosed an undecomposed request of an unknown or Secret kind counts.
func kubeSecretContentRequest(request KubeRequestFact, failClosed bool) bool {
	if request.Subresource != "" {
		return false
	}
	if request.Unknown {
		return failClosed && (request.Resource == "" || request.Resource == kubernetesSecretResource)
	}
	if request.Resource != kubernetesSecretResource {
		return false
	}
	switch request.Verb {
	case KubeVerbGet, KubeVerbList, KubeVerbWatch:
		return request.Source == KubeSourceHTTP || request.RevealsContent
	}
	return false
}

// KubernetesStdinExecRequest reports a pods/exec or pods/attach request that
// streams the caller's stdin into the container (the remote commands are
// not visible in the action), or one whose options are not known (fail
// closed).
func KubernetesStdinExecRequest(facts Facts) bool {
	for _, request := range facts.KubeRequests {
		if request.Resource == "pods" && (request.Stdin || request.Unknown) &&
			(request.Subresource == "exec" || request.Subresource == "attach") {
			return true
		}
	}
	return false
}

// KubeRequestCaps is the cap the Kubernetes request projection hit (one per
// call): the list past maxKubeRequests was cut (bounded.Items). Lost reports
// that the cut dropped a request a reader proves something from (a Secret
// content read, a stdin exec); then the call is judged TRUNCATED. A cut of
// plain requests only (33 x kubectl get pods) loses no proof and is recorded,
// not raised (DET111 T20 review P2-3).
func (f Facts) KubeRequestCaps() (caps bounded.CapSet, lost bool) {
	return f.kubeCut.caps, f.kubeCut.lost
}

// kubeCutRecord is the private record of a Kubernetes request cut.
type kubeCutRecord struct {
	caps bounded.CapSet
	lost bool
}

func projectKubeRequests(input Input, facts Facts) ([]KubeRequestFact, kubeCutRecord) {
	var requests []KubeRequestFact
	if strings.ToLower(input.Tool) == "kubectl" {
		if argv, namespace, ok := exactKubectlArgv(input, facts); ok {
			requests = append(requests, kubectlRequests(0, argv, namespace)...)
		}
		return boundKubeRequests(requests)
	}
	proxyPorts := map[int64]bool{}
	for _, command := range facts.Commands {
		if program := kubeProgram(command); program == "kubectl" || program == "oc" {
			kubectlProxyPorts(kubeWords(command), proxyPorts)
		}
	}
	for _, command := range facts.Commands {
		if command.Effect != EffectExecute && command.Effect != EffectUncertain {
			continue
		}
		words := kubeWords(command)
		switch kubeProgram(command) {
		case "kubectl", "oc":
			// oc is the OpenShift kubectl: the same grammar and requests.
			requests = append(requests, kubectlRequests(command.ID, words, "")...)
		case "curl":
			requests = append(requests, curlKubeRequests(command.ID, words, proxyPorts)...)
		case "wget":
			requests = append(requests, wgetKubeRequests(command.ID, words, proxyPorts)...)
		}
	}
	return boundKubeRequests(requests)
}

// boundKubeRequests keeps the projection bounded without inventing a fact:
// past maxKubeRequests it keeps the requests a reader proves something from
// (kubeRequestProves) first, then the others, in their order, and records
// the cut. It never turns a request into an Unknown one, so a long list of
// plain reads is never a Secret read (DET111 T20 review P2-3).
func boundKubeRequests(requests []KubeRequestFact) ([]KubeRequestFact, kubeCutRecord) {
	var trunc bounded.Truncated
	if trunc.Within(bounded.Items, len(requests), maxKubeRequests) {
		return requests, kubeCutRecord{}
	}
	keep := make([]bool, len(requests))
	kept, proving := 0, 0
	for index, request := range requests {
		if kubeRequestProves(request) {
			proving++
			if kept < maxKubeRequests {
				keep[index] = true
				kept++
			}
		}
	}
	for index := range requests {
		if kept == maxKubeRequests {
			break
		}
		if !keep[index] {
			keep[index] = true
			kept++
		}
	}
	out := make([]KubeRequestFact, 0, maxKubeRequests)
	for index, request := range requests {
		if keep[index] {
			out = append(out, request)
		}
	}
	return out, kubeCutRecord{caps: trunc.Set(), lost: proving > maxKubeRequests}
}

// kubeRequestProves reports a request a Kubernetes reader proves something
// from: a Secret content read (failing closed) or a stdin exec.
func kubeRequestProves(request KubeRequestFact) bool {
	return kubeSecretContentRequest(request, true) ||
		KubernetesStdinExecRequest(Facts{KubeRequests: []KubeRequestFact{request}})
}

func kubeProgram(command CommandFact) string {
	program := strings.ToLower(path.Base(command.Program))
	return strings.TrimSuffix(program, ".exe")
}

// kubeWords is the command's argv with each expanding word kept as its
// static text and awkprog.Hole for every expansion, so a URL such as
// $APISERVER/api/v1/secrets keeps its static path.
func kubeWords(command CommandFact) []string {
	if len(command.Arguments) != len(command.Argv) {
		return command.Argv
	}
	words := make([]string, len(command.Arguments))
	for index, argument := range command.Arguments {
		switch {
		case !argument.Expands:
			words[index] = argument.Value
		case argument.holeText != "":
			words[index] = argument.holeText
		default:
			words[index] = awkprog.Hole
		}
	}
	return words
}

// kubectl argv.

type kubectlOptionArity uint8

const (
	kubectlFlag kubectlOptionArity = iota + 1
	kubectlValue
)

// kubectlGlobalOptions are kubectl's persistent flags; they take the same
// arity under every subcommand.
var kubectlGlobalOptions = map[string]kubectlOptionArity{
	"--context": kubectlValue, "--kubeconfig": kubectlValue, "--cluster": kubectlValue,
	"--user": kubectlValue, "--token": kubectlValue, "-s": kubectlValue, "--server": kubectlValue,
	"--as": kubectlValue, "--as-group": kubectlValue, "--as-uid": kubectlValue,
	"--request-timeout": kubectlValue, "-v": kubectlValue, "--v": kubectlValue,
	"--certificate-authority": kubectlValue, "--client-certificate": kubectlValue,
	"--client-key": kubectlValue, "--tls-server-name": kubectlValue, "--cache-dir": kubectlValue,
	"--username": kubectlValue, "--password": kubectlValue, "--profile": kubectlValue,
	"--profile-output": kubectlValue, "--log-flush-frequency": kubectlValue,
	"--insecure-skip-tls-verify": kubectlFlag, "--match-server-version": kubectlFlag,
	"--warnings-as-errors": kubectlFlag, "--disable-compression": kubectlFlag,
}

var kubectlSubcommandOptions = map[string]map[string]kubectlOptionArity{
	"get": {
		"-A": kubectlFlag, "--all-namespaces": kubectlFlag, "-o": kubectlValue, "--output": kubectlValue,
		"-l": kubectlValue, "--selector": kubectlValue, "--field-selector": kubectlValue,
		"-w": kubectlFlag, "--watch": kubectlFlag, "--watch-only": kubectlFlag,
		"--output-watch-events": kubectlFlag, "--raw": kubectlValue, "--show-labels": kubectlFlag,
		"--no-headers": kubectlFlag, "--sort-by": kubectlValue, "--chunk-size": kubectlValue,
		"--ignore-not-found": kubectlFlag, "-L": kubectlValue, "--label-columns": kubectlValue,
		"--show-kind": kubectlFlag, "--show-managed-fields": kubectlFlag, "--server-print": kubectlFlag,
		"--subresource": kubectlValue, "--allow-missing-template-keys": kubectlFlag,
		"--template": kubectlValue,
	},
	"describe": {
		"-A": kubectlFlag, "--all-namespaces": kubectlFlag, "-l": kubectlValue, "--selector": kubectlValue,
		"--show-events": kubectlFlag, "--chunk-size": kubectlValue,
	},
	"edit": {
		"-o": kubectlValue, "--output": kubectlValue, "--record": kubectlFlag, "--save-config": kubectlFlag,
		"--windows-line-endings": kubectlFlag, "--validate": kubectlValue, "--subresource": kubectlValue,
		"--field-manager": kubectlValue, "--show-managed-fields": kubectlFlag,
	},
	"exec": {
		"-i": kubectlFlag, "--stdin": kubectlFlag, "-t": kubectlFlag, "--tty": kubectlFlag,
		"-c": kubectlValue, "--container": kubectlValue, "-q": kubectlFlag, "--quiet": kubectlFlag,
		"--pod-running-timeout": kubectlValue,
	},
	"attach": {
		"-i": kubectlFlag, "--stdin": kubectlFlag, "-t": kubectlFlag, "--tty": kubectlFlag,
		"-c": kubectlValue, "--container": kubectlValue, "-q": kubectlFlag, "--quiet": kubectlFlag,
		"--pod-running-timeout": kubectlValue,
	},
	"logs": {
		"-c": kubectlValue, "--container": kubectlValue, "-f": kubectlFlag, "--follow": kubectlFlag,
		"-p": kubectlFlag, "--previous": kubectlFlag, "--tail": kubectlValue, "--since": kubectlValue,
		"--timestamps": kubectlFlag, "--all-containers": kubectlFlag, "-l": kubectlValue,
		"--selector": kubectlValue, "--prefix": kubectlFlag,
	},
	"port-forward": {"--address": kubectlValue, "--pod-running-timeout": kubectlValue},
	"proxy": {
		"-p": kubectlValue, "--port": kubectlValue, "--address": kubectlValue, "--accept-hosts": kubectlValue,
		"--accept-paths": kubectlValue, "--reject-paths": kubectlValue, "--api-prefix": kubectlValue,
		"-w": kubectlValue, "--www": kubectlValue, "-P": kubectlValue, "--www-prefix": kubectlValue,
		"-u": kubectlValue, "--unix-socket": kubectlValue, "--disable-filter": kubectlFlag,
		"--keepalive": kubectlValue, "--reject-methods": kubectlValue,
	},
	"cp": {"-c": kubectlValue, "--container": kubectlValue, "--no-preserve": kubectlFlag, "--retries": kubectlValue},
}

// kubectlArgv is one kubectl command line split into options and operands.
type kubectlArgv struct {
	subcommand string
	operands   []string
	command    []string // after "--"
	values     map[string]string
	flags      map[string]bool
	unknown    bool // an option kubectl's grammar for the subcommand does not have
}

func parseKubectlArgv(argv []string) (kubectlArgv, bool) {
	parsed := kubectlArgv{values: map[string]string{}, flags: map[string]bool{}}
	if len(argv) < 2 {
		return parsed, false
	}
	// The subcommand is the first operand; global options may precede it.
	for index := 1; index < len(argv); index++ {
		word := argv[index]
		if word == "--" {
			parsed.command = argv[index+1:]
			break
		}
		if parsed.subcommand == "auth" && len(parsed.operands) > 0 && parsed.operands[0] == "can-i" {
			parsed.operands = append(parsed.operands, word)
			continue
		}
		if !strings.HasPrefix(word, "-") || word == "-" {
			if parsed.subcommand == "" {
				parsed.subcommand = word
			} else {
				parsed.operands = append(parsed.operands, word)
				if parsed.subcommand == "exec" && len(parsed.operands) == 1 {
					// Legacy form: kubectl exec POD COMMAND [args...].
					if index+1 < len(argv) && argv[index+1] != "--" &&
						!strings.HasPrefix(argv[index+1], "-") {
						parsed.command = argv[index+1:]
						break
					}
				}
			}
			continue
		}
		name, value, joined := strings.Cut(word, "=")
		options := kubectlSubcommandOptions[parsed.subcommand]
		if !strings.HasPrefix(word, "--") && len(word) > 2 && !joined {
			// A short option with its value attached (-oyaml, -nkube-system)
			// or a bundle of short flags (-it).
			short := word[:2]
			if arity, ok := kubectlOptionLookup(short, options); ok && arity == kubectlValue {
				parsed.values[short] = word[2:]
				continue
			}
			bundle := true
			for _, letter := range word[1:] {
				if arity, ok := kubectlOptionLookup("-"+string(letter), options); !ok || arity != kubectlFlag {
					bundle = false
					break
				}
			}
			if !bundle {
				parsed.unknown = true
				continue
			}
			for _, letter := range word[1:] {
				parsed.flags["-"+string(letter)] = true
			}
			continue
		}
		arity, ok := kubectlOptionLookup(name, options)
		if !ok {
			parsed.unknown = true
			continue
		}
		if arity == kubectlFlag {
			parsed.flags[name] = !joined || apiserverBool(value)
			continue
		}
		if !joined {
			if index+1 >= len(argv) {
				parsed.unknown = true
				continue
			}
			index++
			value = argv[index]
		}
		parsed.values[name] = value
	}
	return parsed, parsed.subcommand != ""
}

func kubectlOptionLookup(name string, options map[string]kubectlOptionArity) (kubectlOptionArity, bool) {
	switch name {
	case "-n", "--namespace":
		return kubectlValue, true
	case "-f", "--filename", "-k", "--kustomize":
		if _, isLogs := options["--follow"]; isLogs && name == "-f" {
			return kubectlFlag, true
		}
		return kubectlValue, true
	case "-R", "--recursive":
		return kubectlFlag, true
	}
	if arity, ok := options[name]; ok {
		return arity, true
	}
	arity, ok := kubectlGlobalOptions[name]
	return arity, ok
}

func (parsed kubectlArgv) value(names ...string) (string, bool) {
	for _, name := range names {
		if value, ok := parsed.values[name]; ok {
			return value, true
		}
	}
	return "", false
}

func (parsed kubectlArgv) flag(names ...string) bool {
	for _, name := range names {
		if parsed.flags[name] {
			return true
		}
	}
	return false
}

func kubectlRequests(commandID int64, argv []string, schemaNamespace string) []KubeRequestFact {
	parsed, ok := parseKubectlArgv(argv)
	if !ok {
		return nil
	}
	namespace, _ := parsed.value("-n", "--namespace")
	if namespace == "" {
		namespace = schemaNamespace
	}
	base := KubeRequestFact{CommandID: commandID, Source: KubeSourceKubectl, Namespace: namespace}
	switch parsed.subcommand {
	case "get", "describe", "edit":
		if raw, ok := parsed.value("--raw"); ok && parsed.subcommand == "get" {
			request, kube := kubeURLPathRequest("GET", raw, true)
			if !kube {
				return nil
			}
			// --raw prints the apiserver's response body: the whole object.
			request.CommandID, request.Source = commandID, KubeSourceKubectl
			request.RevealsContent = true
			return []KubeRequestFact{request}
		}
		return kubectlReadRequests(base, parsed)
	case "exec", "attach":
		request := base
		request.Resource, request.Subresource, request.Verb = "pods", parsed.subcommand, KubeVerbCreate
		request.Stdin = parsed.flag("-i", "--stdin")
		request.TTY = parsed.flag("-t", "--tty")
		request.Command = len(parsed.command) > 0
		if len(parsed.operands) > 0 {
			request.Name = parsed.operands[0]
		}
		request.Unknown = parsed.unknown || len(parsed.operands) == 0
		return []KubeRequestFact{request}
	case "cp":
		request := base
		request.Resource, request.Subresource, request.Verb = "pods", "exec", KubeVerbCreate
		request.Command = true
		// Copying into a pod streams a local tar archive into the exec.
		request.Stdin = len(parsed.operands) == 2 && strings.Contains(parsed.operands[1], ":")
		request.Unknown = parsed.unknown || len(parsed.operands) != 2
		return []KubeRequestFact{request}
	case "logs":
		request := base
		request.Resource, request.Subresource, request.Verb = "pods", "log", KubeVerbGet
		if len(parsed.operands) > 0 {
			request.Name = parsed.operands[0]
		}
		return []KubeRequestFact{request}
	case "port-forward":
		request := base
		request.Resource, request.Subresource, request.Verb = "pods", "portforward", KubeVerbCreate
		if len(parsed.operands) > 0 {
			request.Name = parsed.operands[0]
		}
		return []KubeRequestFact{request}
	case "proxy":
		request := base
		request.Verb = KubeVerbProxy
		return []KubeRequestFact{request}
	case "auth":
		if len(parsed.operands) == 0 || parsed.operands[0] != "can-i" {
			return nil
		}
		request := base
		request.Verb, request.Group = KubeVerbCreate, "authorization.k8s.io"
		request.Version, request.Resource = "v1", "selfsubjectaccessreviews"
		return []KubeRequestFact{request}
	}
	return nil
}

// kubectlReadRequests is one request per resource type a get, describe or
// edit names (secrets, pod/x, secret/a secret/b, pods,secrets).
func kubectlReadRequests(base KubeRequestFact, parsed kubectlArgv) []KubeRequestFact {
	if len(parsed.operands) == 0 {
		if _, ok := parsed.value("-f", "--filename", "-k", "--kustomize"); ok {
			// Objects named by a file: their kinds are not in the action. A
			// read that prints no object content (the table of get, describe)
			// reads no Secret content whatever the file names, so only one
			// that prints objects (-o json|yaml, a data template, edit) or
			// whose options are not known is undecomposed (DET111 T20 review
			// P2-2: kubectl get -f deploy.yaml is no Secret read).
			request := base
			request.Verb = KubeVerbGet
			request.RevealsContent = kubectlPrintsObjects(parsed)
			request.Unknown = request.RevealsContent || parsed.unknown
			return []KubeRequestFact{request}
		}
		return nil
	}
	type typed struct{ kind, name string }
	var targets []typed
	if strings.Contains(parsed.operands[0], "/") {
		for _, operand := range parsed.operands {
			kind, name, _ := strings.Cut(operand, "/")
			targets = append(targets, typed{kind, name})
		}
	} else {
		for _, kind := range strings.Split(parsed.operands[0], ",") {
			if len(parsed.operands) == 1 {
				targets = append(targets, typed{kind: kind})
			}
			for _, name := range parsed.operands[1:] {
				targets = append(targets, typed{kind, name})
			}
		}
	}
	watch := parsed.flag("-w", "--watch", "--watch-only")
	allNamespaces := parsed.flag("-A", "--all-namespaces")
	_, selector := parsed.value("-l", "--selector")
	seen := map[typed]bool{}
	var requests []KubeRequestFact
	for _, target := range targets {
		if seen[target] {
			continue
		}
		seen[target] = true
		request := base
		request.Group, request.Resource = kubectlResource(target.kind)
		request.Name = target.name
		request.AllNamespaces = allNamespaces
		request.LabelSelector = selector
		switch {
		case watch:
			request.Verb = KubeVerbWatch
		case target.name != "":
			request.Verb = KubeVerbGet
		default:
			request.Verb = KubeVerbList
		}
		request.RevealsContent = kubectlPrintsObjects(parsed)
		secretLike := strings.Contains(strings.ToLower(target.kind), "secret")
		if request.Resource == "" || strings.Contains(target.kind, awkprog.Hole) ||
			strings.Contains(target.name, awkprog.Hole) && secretLike {
			// A resource kind the action does not spell statically.
			request.Unknown = true
		}
		if parsed.unknown && (secretLike || request.Resource == kubernetesSecretResource) {
			// A Secret read whose options kubectl's grammar does not have:
			// what it prints is not known, so it fails closed.
			request.Unknown = true
		}
		requests = append(requests, request)
	}
	return requests
}

// kubectlPrintsObjects reports a kubectl read that prints the objects it
// reads: edit, or a get whose output (-o, --template) shows their content.
func kubectlPrintsObjects(parsed kubectlArgv) bool {
	switch parsed.subcommand {
	case "edit":
		return true
	case "get":
		output, _ := parsed.value("-o", "--output")
		template, hasTemplate := parsed.value("--template")
		return kubectlOutputRevealsContent(output) || hasTemplate && kubectlSelectorRevealsContent(template)
	}
	return false
}

// kubectlResource resolves a kubectl resource spelling (secret, secrets,
// secrets.v1., po, pods) to its API group and plural resource name.
func kubectlResource(kind string) (group, resource string) {
	kind = strings.ToLower(kind)
	if kind == "" || strings.Contains(kind, awkprog.Hole) {
		return "", ""
	}
	name, qualifier, _ := strings.Cut(kind, ".")
	switch name {
	case "secret", "secrets":
		if qualifier == "" || qualifier == "v1" || qualifier == "v1." {
			return "", kubernetesSecretResource
		}
		// A Secret spelled with a group qualifier the core API does not
		// have: kubectl resolves it from discovery.
		return "", ""
	case "pod", "pods", "po":
		return "", "pods"
	case "configmap", "configmaps", "cm":
		return "", "configmaps"
	case "serviceaccount", "serviceaccounts", "sa":
		return "", "serviceaccounts"
	}
	return qualifier, kind
}

func kubectlOutputRevealsContent(output string) bool {
	format, selector, _ := strings.Cut(output, "=")
	switch strings.ToLower(format) {
	case "json", "yaml":
		return true
	case "jsonpath", "jsonpath-as-json", "go-template", "template", "custom-columns":
		return kubectlSelectorRevealsContent(selector)
	case "jsonpath-file", "go-template-file", "custom-columns-file", "template-file":
		// The selector is in a file the action does not show.
		return true
	}
	return strings.Contains(output, awkprog.Hole)
}

// kubectlSelectorRevealsContent reports whether an output template may print
// a Secret's data: it names data or stringData, prints whole objects, or is
// not static.
func kubectlSelectorRevealsContent(selector string) bool {
	lower := strings.ToLower(selector)
	if selector == "" || strings.Contains(selector, awkprog.Hole) ||
		strings.Contains(lower, ".data") || strings.Contains(lower, "stringdata") ||
		strings.Contains(lower, `"data"`) || strings.Contains(lower, `'data'`) {
		return true
	}
	body := strings.Trim(strings.TrimSpace(selector), "{}")
	switch strings.TrimSpace(body) {
	case "", ".", "@", ".items", ".items[*]", "range .items", "json .", "toJson .":
		return true
	}
	return false
}

func kubectlProxyPorts(argv []string, ports map[int64]bool) {
	parsed, ok := parseKubectlArgv(argv)
	if !ok || parsed.subcommand != "proxy" {
		return
	}
	value, set := parsed.value("-p", "--port")
	if !set {
		ports[8001] = true
		return
	}
	if port, err := strconv.ParseInt(value, 10, 64); err == nil && port > 0 && port <= 65535 {
		ports[port] = true
	} else {
		// A random or dynamic proxy port: any loopback port may be it.
		ports[0] = true
	}
}

// HTTP requests (curl, wget).

var curlDataOptions = map[string]bool{
	"--data": true, "--data-ascii": true, "--data-binary": true, "--data-raw": true,
	"--data-urlencode": true, "--json": true, "--form": true, "--form-string": true,
}

func curlKubeRequests(commandID int64, argv []string, proxyPorts map[int64]bool) []KubeRequestFact {
	parsed := parseCurlArgv(argv)
	var requests []KubeRequestFact
	for _, target := range parsed.Targets {
		cacert, bearer, data, get := false, false, false, false
		for _, option := range parsed.Options {
			if option.Group != target.Group {
				continue
			}
			switch {
			case option.Canonical == "--cacert" || option.Canonical == "--capath":
				cacert = cacert || strings.Contains(option.Value, "/var/run/secrets/kubernetes.io/")
			case option.Canonical == "--oauth2-bearer":
				bearer = true
			case option.Canonical == "--header":
				bearer = bearer || kubeBearerHeader(option.Value)
			case curlDataOptions[option.Canonical]:
				data = true
			case option.Canonical == "--get":
				get = true
			}
		}
		method := strings.ToUpper(target.Method)
		switch {
		case method != "":
		case target.Head:
			method = "HEAD"
		case target.UploadSet:
			method = "PUT"
		case data && !get:
			method = "POST"
		default:
			method = "GET"
		}
		if strings.Contains(method, strings.ToUpper(awkprog.Hole)) {
			method = ""
		}
		if request, ok := kubeHTTPRequest(method, target.Value, cacert, bearer, proxyPorts); ok {
			request.CommandID = commandID
			requests = append(requests, request)
		}
	}
	return requests
}

func wgetKubeRequests(commandID int64, argv []string, proxyPorts map[int64]bool) []KubeRequestFact {
	parsed := parseWgetArgv(argv)
	method := "GET"
	switch {
	case parsed.MethodSet:
		method = strings.ToUpper(parsed.Method)
	case parsed.PostDataSet || parsed.PostFileSet:
		method = "POST"
	}
	if strings.Contains(method, strings.ToUpper(awkprog.Hole)) {
		method = ""
	}
	cacert, bearer := false, false
	for index, word := range argv {
		cacert = cacert || strings.HasPrefix(word, "--ca-certificate") &&
			strings.Contains(word, "/var/run/secrets/kubernetes.io/")
		if value, ok := strings.CutPrefix(word, "--header="); ok {
			bearer = bearer || kubeBearerHeader(value)
		} else if word == "--header" && index+1 < len(argv) {
			bearer = bearer || kubeBearerHeader(argv[index+1])
		}
	}
	var requests []KubeRequestFact
	for _, target := range parsed.Targets {
		if request, ok := kubeHTTPRequest(method, target, cacert, bearer, proxyPorts); ok {
			request.CommandID = commandID
			requests = append(requests, request)
		}
	}
	return requests
}

type kubeEvidence uint8

const (
	kubeEvidenceNone kubeEvidence = iota
	// kubeEvidenceDynamicHost: the host is not static ($APISERVER), or the
	// host is not known as an apiserver (a bare IP:443) but the request
	// carries a bearer token, the credential an apiserver client sends
	// (rel-1-0-10:GAP-1860). Either way only a path that decomposes as a
	// Kubernetes API path is a request.
	kubeEvidenceDynamicHost
	// kubeEvidenceAPIServer: the target is an apiserver (the in-cluster
	// service name, port 6443, a kubectl proxy port on loopback, a managed
	// control plane host, or the service-account CA bundle).
	kubeEvidenceAPIServer
)

// kubeHTTPRequest decomposes one HTTP URL addressed to a Kubernetes
// apiserver. ok is false for a URL that is not an apiserver request.
func kubeHTTPRequest(method, raw string, cacert, bearer bool, proxyPorts map[int64]bool) (KubeRequestFact, bool) {
	scheme, authority, rest := splitKubeURL(raw)
	evidence := kubeHostEvidence(scheme, authority, proxyPorts)
	if cacert && evidence == kubeEvidenceNone {
		evidence = kubeEvidenceAPIServer
	}
	if bearer && evidence == kubeEvidenceNone {
		evidence = kubeEvidenceDynamicHost
	}
	if evidence == kubeEvidenceNone {
		return KubeRequestFact{}, false
	}
	request, kube := kubeURLPathRequest(method, rest, evidence == kubeEvidenceAPIServer)
	if !kube {
		return KubeRequestFact{}, false
	}
	if request.Unknown && evidence != kubeEvidenceAPIServer &&
		request.Resource != kubernetesSecretResource {
		// A dynamic host is apiserver evidence only for a path that
		// decomposes; an opaque REST call stays out of the fact.
		return KubeRequestFact{}, false
	}
	request.Source = KubeSourceHTTP
	return request, true
}

// kubeBearerHeader reports an HTTP header value that sends a bearer token
// (Authorization: Bearer ...).
func kubeBearerHeader(value string) bool {
	name, token, found := strings.Cut(value, ":")
	if !found || !strings.EqualFold(strings.TrimSpace(name), "authorization") {
		return false
	}
	scheme, _, _ := strings.Cut(strings.TrimSpace(token), " ")
	return strings.EqualFold(scheme, "bearer")
}

// splitKubeURL splits a curl or wget URL (the scheme is optional) into its
// scheme, authority and the path with its query.
func splitKubeURL(raw string) (scheme, authority, rest string) {
	if before, after, found := strings.Cut(raw, "://"); found && !strings.Contains(before, "/") {
		scheme, raw = strings.ToLower(before), after
	}
	end := strings.IndexAny(raw, "/?#")
	if end < 0 {
		return scheme, raw, ""
	}
	return scheme, raw[:end], raw[end:]
}

var kubeServiceHosts = map[string]bool{
	"kubernetes": true, "kubernetes.default": true, "kubernetes.default.svc": true,
	"kubernetes.default.svc.cluster.local": true,
}

func kubeHostEvidence(scheme, authority string, proxyPorts map[int64]bool) kubeEvidence {
	if strings.Contains(authority, awkprog.Hole) {
		return kubeEvidenceDynamicHost
	}
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	host, port := authority, int64(0)
	if strings.HasPrefix(host, "[") {
		if end := strings.Index(host, "]"); end > 0 {
			host, authority = host[1:end], host[end+1:]
			if value, ok := strings.CutPrefix(authority, ":"); ok {
				port, _ = strconv.ParseInt(value, 10, 64)
			}
		}
	} else if before, after, found := strings.Cut(host, ":"); found {
		host = before
		port, _ = strconv.ParseInt(after, 10, 64)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	switch {
	case kubeServiceHosts[host], port == 6443,
		strings.HasSuffix(host, ".eks.amazonaws.com"), strings.HasSuffix(host, ".azmk8s.io"):
		return kubeEvidenceAPIServer
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		if port == 0 && scheme != "https" {
			port = 80
		}
		if port == 8001 || proxyPorts[port] || proxyPorts[0] {
			return kubeEvidenceAPIServer
		}
	}
	return kubeEvidenceNone
}

// Kubernetes API paths (adapted from denoland/clawpatrol, MIT).

var kubeSpecialVerbs = map[string]bool{KubeVerbWatch: true, KubeVerbProxy: true}

var kubeNamespaceSubresources = map[string]bool{"status": true, "finalize": true}

// kubeURLPathRequest decomposes the path and query of an apiserver request
// into the request tuple. kube is false for a path that is not a Kubernetes
// API path (no /api or /apis prefix). A Kubernetes path it cannot
// decompose is an Unknown request when strict holds (the target is known to
// be an apiserver), and not a request otherwise.
func kubeURLPathRequest(method, rest string, strict bool) (request KubeRequestFact, kube bool) {
	rawPath, rawQuery, _ := strings.Cut(rest, "?")
	rawPath, _, _ = strings.Cut(rawPath, "#")
	trimmed := strings.Trim(rawPath, "/")
	head, _, _ := strings.Cut(trimmed, "/")
	switch {
	case head == "api" || head == "apis":
	case kubeMetaPath(trimmed):
		return KubeRequestFact{Verb: KubeVerbMeta}, true
	case strings.HasPrefix(head, awkprog.Hole) && strict:
		return KubeRequestFact{Unknown: true}, true
	default:
		return KubeRequestFact{}, false
	}
	unknown := KubeRequestFact{Unknown: true}
	if strings.Contains(rest, awkprog.Hole) || strings.ContainsAny(rawPath, "{}[]\\") {
		// A dynamic segment or a curl URL glob: the addressed resource is
		// not static.
		unknown.Resource = kubeSecretMention(rawPath)
		return unknown, strict || unknown.Resource != ""
	}
	if kubeMetaPath(trimmed) {
		return KubeRequestFact{Verb: KubeVerbMeta}, true
	}
	parts := strings.Split(trimmed, "/")
	for index, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil || strings.Contains(decoded, "/") || decoded == "." || decoded == ".." {
			unknown.Resource = kubeSecretMention(rawPath)
			return unknown, strict || unknown.Resource != ""
		}
		parts[index] = decoded
	}
	switch parts[0] {
	case "api":
		if len(parts) < 2 {
			return unknown, strict
		}
		request.Version, parts = parts[1], parts[2:]
	case "apis":
		if len(parts) < 3 {
			return unknown, strict
		}
		request.Group, request.Version, parts = parts[1], parts[2], parts[3:]
	}
	if len(parts) == 0 {
		return KubeRequestFact{Verb: KubeVerbMeta}, true
	}
	if kubeSpecialVerbs[parts[0]] {
		// A bare path-prefix verb addresses nothing.
		if len(parts) < 2 {
			return unknown, strict
		}
		request.Verb, parts = parts[0], parts[1:]
	}
	if parts[0] == "namespaces" && len(parts) > 1 {
		request.Namespace = parts[1]
		if len(parts) > 2 && !kubeNamespaceSubresources[parts[2]] {
			parts = parts[2:]
		}
	}
	if parts[0] == "" {
		return unknown, strict
	}
	request.Resource = parts[0]
	if len(parts) > 1 {
		request.Name = parts[1]
	}
	if len(parts) > 2 && request.Verb != KubeVerbProxy {
		request.Subresource = parts[2]
	}
	if request.Verb == "" {
		verb, ok := kubeVerbFromMethod(method, request.Name)
		if !ok {
			unknown.Resource = request.Resource
			return unknown, true
		}
		request.Verb = verb
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		unknown.Resource = request.Resource
		return unknown, true
	}
	if value, ok := query["watch"]; ok && len(value) > 0 && apiserverBool(value[0]) &&
		(request.Verb == KubeVerbGet || request.Verb == KubeVerbList) {
		request.Verb = KubeVerbWatch
	}
	request.Stdin = kubeQueryBool(query, "stdin")
	request.TTY = kubeQueryBool(query, "tty")
	request.Command = len(query["command"]) > 0
	request.LabelSelector = len(query["labelSelector"]) > 0
	request.AllNamespaces = request.Namespace == "" && request.Name == "" &&
		(request.Verb == KubeVerbList || request.Verb == KubeVerbWatch)
	return request, true
}

func kubeSecretMention(rawPath string) string {
	if strings.Contains(strings.ToLower(rawPath), "secret") {
		return kubernetesSecretResource
	}
	return ""
}

// kubeVerbFromMethod maps an HTTP method to the verb the apiserver derives
// from it. A read without a name reads the whole collection (list).
func kubeVerbFromMethod(method, name string) (string, bool) {
	switch strings.ToUpper(method) {
	case "GET", "HEAD":
		if name == "" {
			return KubeVerbList, true
		}
		return KubeVerbGet, true
	case "POST":
		return KubeVerbCreate, true
	case "PUT":
		return KubeVerbUpdate, true
	case "PATCH":
		return KubeVerbPatch, true
	case "DELETE":
		return KubeVerbDelete, true
	}
	return "", false
}

func kubeQueryBool(query url.Values, key string) bool {
	value, ok := query[key]
	return ok && len(value) > 0 && apiserverBool(value[0])
}

// apiserverBool is how kube-apiserver reads a boolean query parameter or
// kubectl a boolean flag value: only "0" and a case-insensitive "false" are
// false.
func apiserverBool(value string) bool {
	return value != "0" && !strings.EqualFold(value, "false")
}

// kubeMetaPath reports a non-resource apiserver URI (discovery, health,
// version, OpenAPI, metrics) that kubectl and client-go probe.
func kubeMetaPath(trimmed string) bool {
	switch trimmed {
	case "api", "apis", "healthz", "livez", "readyz", "version", "metrics", "openapi":
		return true
	}
	if strings.HasPrefix(trimmed, "openapi/") {
		return true
	}
	if rest, ok := strings.CutPrefix(trimmed, "api/"); ok {
		return !strings.Contains(rest, "/")
	}
	if rest, ok := strings.CutPrefix(trimmed, "apis/"); ok {
		return strings.Count(rest, "/") <= 1
	}
	return false
}
