//go:build darwin

package hwprofile

import (
	"encoding/json"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

func detectCPU(p *SystemProfile) {
	if runtime.GOOS != "darwin" {
		return
	}
	out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output()
	if err == nil {
		p.CPUName = strings.TrimSpace(string(out))
	}
	p.CPUCores = runtime.NumCPU()
}

func detectRAM(p *SystemProfile) {
	if runtime.GOOS != "darwin" {
		return
	}
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err == nil {
		bytes, _ := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
		p.TotalRAMGB = float64(bytes) / (1024 * 1024 * 1024)
	}

	// Available memory from vm_stat
	vmOut, err := exec.Command("vm_stat").Output()
	if err == nil {
		p.AvailableRAMGB = parseVMStatFreeGB(string(vmOut))
	}
}

func parseVMStatFreeGB(vmstat string) float64 {
	var freePages, inactivePages uint64
	for _, line := range strings.Split(vmstat, "\n") {
		if strings.HasPrefix(line, "Pages free:") {
			freePages = parseVMStatPages(line)
		}
		if strings.HasPrefix(line, "Pages inactive:") {
			inactivePages = parseVMStatPages(line)
		}
	}
	pageSize := uint64(4096) // macOS default
	return float64((freePages+inactivePages)*pageSize) / (1024 * 1024 * 1024)
}

func parseVMStatPages(line string) uint64 {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0
	}
	s := strings.TrimRight(parts[len(parts)-1], ".")
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// detectAppleSilicon uses system_profiler to detect Apple GPU with unified memory.
func detectAppleSilicon() []GpuInfo {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return nil
	}
	out, err := exec.Command("system_profiler", "SPDisplaysDataType", "-json").Output()
	if err != nil {
		return nil
	}

	var result struct {
		SPDisplaysDataType []struct {
			SPDisplaysChipsetModel string `json:"sppci_model"`
			SPDisplaysVRAM        string `json:"sppci_vram"` // e.g. "16 GB" or "Shared"
			SPDisplaysBus         string `json:"sppci_bus"`
		} `json:"SPDisplaysDataType"`
	}
	if json.Unmarshal(out, &result) != nil {
		return nil
	}

	var gpus []GpuInfo
	for _, d := range result.SPDisplaysDataType {
		name := d.SPDisplaysChipsetModel
		if name == "" {
			continue
		}
		gpu := GpuInfo{
			Name:          name,
			Backend:       "metal",
			UnifiedMemory: true,
		}
		// For Apple Silicon, VRAM is shared with system RAM
		// Parse the VRAM string or use total RAM
		vram := strings.TrimSpace(d.SPDisplaysVRAM)
		if strings.Contains(strings.ToLower(vram), "shared") || vram == "" {
			// Unified memory — use total system RAM as VRAM
			ramOut, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
			if err == nil {
				bytes, _ := strconv.ParseUint(strings.TrimSpace(string(ramOut)), 10, 64)
				gpu.VRAMTotalGB = float64(bytes) / (1024 * 1024 * 1024)
			}
		} else {
			// Parse "16 GB" format
			parts := strings.Fields(vram)
			if len(parts) >= 1 {
				v, _ := strconv.ParseFloat(parts[0], 64)
				gpu.VRAMTotalGB = v
			}
		}
		gpus = append(gpus, gpu)
	}
	return gpus
}
