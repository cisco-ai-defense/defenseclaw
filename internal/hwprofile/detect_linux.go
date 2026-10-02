//go:build linux

package hwprofile

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

func detectCPU(p *SystemProfile) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		p.CPUCores = runtime.NumCPU()
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				p.CPUName = strings.TrimSpace(parts[1])
				break
			}
		}
	}
	p.CPUCores = runtime.NumCPU()
}

func detectRAM(p *SystemProfile) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			p.TotalRAMGB = parseMemInfoKB(line) / (1024 * 1024)
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			p.AvailableRAMGB = parseMemInfoKB(line) / (1024 * 1024)
		}
	}
}

func parseMemInfoKB(line string) float64 {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0
	}
	v, _ := strconv.ParseFloat(parts[1], 64)
	return v
}
