package firewall

// Compiler generates platform-specific firewall rules from a FirewallConfig.
// Implementations must be pure Go — no privileged operations.
type Compiler interface {
	// Platform returns the backend name ("pfctl" or "iptables").
	Platform() string

	// Compile converts a FirewallConfig into a slice of rule strings.
	// This is pure in-memory work — no system calls, no root required.
	Compile(cfg *FirewallConfig) ([]string, error)

	// ValidateArg checks that a string is safe to use as a rule argument.
	ValidateArg(arg string) error

	// ApplyCommand returns the shell command an administrator should run
	// to load the rules file at rulesPath. Never executes it.
	ApplyCommand(rulesPath string) string

	// RemoveCommand returns the shell command an administrator should run
	// to remove the firewall rules. Never executes it.
	RemoveCommand() string
}
