package agentotel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ToolClaude = "claude"
	ToolCodex  = "codex"
	ToolAll    = "all"
)

func deriveIngestHost(raw string) (string, string, error) {
	host := strings.TrimSpace(raw)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimRight(host, "/")
	if host == "" {
		return "", "", fmt.Errorf("splunk host must not be empty")
	}

	if realm := extractRealm(host); realm != "" {
		ingest := fmt.Sprintf("ingest.%s.signalfx.com", realm)
		return ingest, fmt.Sprintf("derived ingest host %q from %q (realm %s)", ingest, raw, realm), nil
	}

	if strings.HasPrefix(host, "ingest.") && strings.HasSuffix(host, ".signalfx.com") {
		return host, "", nil
	}

	if !strings.Contains(host, ".") {
		ingest := fmt.Sprintf("ingest.%s.signalfx.com", host)
		return ingest, fmt.Sprintf("interpreted %q as realm and derived ingest host %q", raw, ingest), nil
	}

	return host, "", nil
}

func extractRealm(host string) string {
	const suffix = ".observability.splunkcloud.com"
	if !strings.HasSuffix(host, suffix) {
		return ""
	}
	prefix := strings.TrimSuffix(host, suffix)
	if strings.HasPrefix(prefix, "app.") {
		return strings.TrimPrefix(prefix, "app.")
	}
	if strings.HasPrefix(prefix, "ingest.") {
		return strings.TrimPrefix(prefix, "ingest.")
	}
	if prefix != "" && !strings.Contains(prefix, ".") {
		return prefix
	}
	return ""
}

func mergeResourceAttributes(existing string, extra map[string]string) string {
	attrs := map[string]string{}
	for _, part := range strings.Split(existing, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		attrs[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	for k, v := range extra {
		if strings.TrimSpace(v) == "" {
			continue
		}
		attrs[k] = sanitizeResourceValue(v)
	}
	if len(attrs) == 0 {
		return ""
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+attrs[k])
	}
	return strings.Join(out, ",")
}

func sanitizeResourceValue(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case strings.ContainsRune("._:-/", r):
			b.WriteRune(r)
		default:
			for _, by := range []byte(string(r)) {
				fmt.Fprintf(&b, "%%%02X", by)
			}
		}
	}
	return b.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func shouldUseClaudeBedrockForConfig(env map[string]interface{}) bool {
	if isTruthy(configEnvValue(env, "CLAUDE_CODE_USE_BEDROCK")) {
		return true
	}
	if strings.TrimSpace(firstNonEmpty(
		configEnvValue(env, "ANTHROPIC_API_KEY"),
		configEnvValue(env, "ANTHROPIC_AUTH_TOKEN"),
		configEnvValue(env, "CLAUDE_CODE_OAUTH_TOKEN"),
	)) != "" {
		return false
	}
	if strings.TrimSpace(configEnvValue(env, "AWS_BEARER_TOKEN_BEDROCK")) != "" {
		return true
	}

	homeDir, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(homeDir) == "" {
		return false
	}
	if hasClaudeFirstPartyAuth(filepath.Join(homeDir, ".claude.json")) {
		return false
	}
	if fileExists(filepath.Join(homeDir, ".aws-bedrock-cc-creds.json")) {
		return true
	}
	return settingsEnableClaudeBedrock(
		filepath.Join(homeDir, ".claude", "settings.json"),
		filepath.Join(homeDir, ".claude", "settings.local.json"),
	)
}

func configEnvValue(env map[string]interface{}, key string) string {
	value, ok := env[key]
	if ok {
		switch v := value.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return v
			}
		}
	}
	return os.Getenv(key)
}

func hasClaudeFirstPartyAuth(path string) bool {
	return jsonFileContainsAnyKey(path,
		"oauthAccount",
		"accessToken",
		"refreshToken",
		"customApiKeyResponses",
	)
}

func settingsEnableClaudeBedrock(paths ...string) bool {
	for _, path := range paths {
		if jsonFileContainsAnyKey(path, "awsCredentialExport", "awsAuthRefresh") {
			return true
		}
	}
	return false
}

func jsonFileContainsAnyKey(path string, keys ...string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var decoded interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return false
	}
	keySet := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		keySet[key] = struct{}{}
	}
	return containsAnyJSONKey(decoded, keySet)
}

func containsAnyJSONKey(value interface{}, keys map[string]struct{}) bool {
	switch v := value.(type) {
	case map[string]interface{}:
		for key, child := range v {
			if _, ok := keys[key]; ok {
				return true
			}
			if containsAnyJSONKey(child, keys) {
				return true
			}
		}
	case []interface{}:
		for _, child := range v {
			if containsAnyJSONKey(child, keys) {
				return true
			}
		}
	}
	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
