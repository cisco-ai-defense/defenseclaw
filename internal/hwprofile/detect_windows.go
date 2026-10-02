//go:build windows

package hwprofile

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

func detectCPU(p *SystemProfile) {
	out, _ := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_Processor).Name").Output()
	p.CPUName = strings.TrimSpace(string(out))
	p.CPUCores = runtime.NumCPU()
}

func detectRAM(p *SystemProfile) {
	out, _ := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory").Output()
	bytes, _ := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	p.TotalRAMGB = float64(bytes) / (1024 * 1024 * 1024)

	out2, _ := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory").Output()
	kb, _ := strconv.ParseUint(strings.TrimSpace(string(out2)), 10, 64)
	p.AvailableRAMGB = float64(kb) / (1024 * 1024)
}
