package config

import "sync"

// keyStore holds in-memory API keys injected at startup by the enterprise
// token hydration layer. Keys stored here take priority over os.Getenv
// in ResolvedAPIKey() so that secrets fetched from an external vault
// never touch the process environment.
var (
	keyStoreMu  sync.RWMutex
	keyStoreMap = make(map[string]string)
)

// SetKey stores an API key in the in-memory key store under the given
// env var name. Subsequent calls to ResolvedAPIKey() and
// CiscoAIDefenseConfig.ResolvedAPIKey() will find it here before
// consulting os.Getenv.
func SetKey(envVarName, value string) {
	keyStoreMu.Lock()
	keyStoreMap[envVarName] = value
	keyStoreMu.Unlock()
}

// GetKey returns the in-memory key for the given env var name, or
// empty string if not set. The bool return indicates presence.
func GetKey(envVarName string) (string, bool) {
	keyStoreMu.RLock()
	v, ok := keyStoreMap[envVarName]
	keyStoreMu.RUnlock()
	return v, ok
}
