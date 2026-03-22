// Package platform selects the appropriate firewall compiler for the current OS.
// Kept separate from internal/firewall to avoid an import cycle between the
// parent package (which defines the Compiler interface and shared types) and
// the pfctl/iptables sub-packages (which implement the interface by importing
// the parent package).
package platform

import (
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/firewall"
	"github.com/defenseclaw/defenseclaw/internal/firewall/iptables"
	"github.com/defenseclaw/defenseclaw/internal/firewall/pfctl"
)

// NewCompiler returns the appropriate Compiler for the current OS.
// darwin → pfctl, everything else → iptables.
func NewCompiler() firewall.Compiler {
	if runtime.GOOS == "darwin" {
		return pfctl.New()
	}
	return iptables.New()
}
