// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactEndpointSecurityProductDisableSourceCandidates(t *testing.T) {
	tests := []struct {
		name    string
		command string
		dialect Dialect
		want    bool
	}{
		{
			name: "carbon black daemon conditional",
			command: `if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "6" ]; then
service cbdaemon stop
chkconfig off cbdaemon
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "7" ];
systemctl stop cbdaemon
systemctl disable cbdaemon
fi`,
			dialect: DialectPOSIX,
		},
		{
			name:    "falcon sensor stop and disable",
			command: "sudo systemctl stop falcon-sensor.service\nsudo systemctl disable falcon-sensor.service",
			dialect: DialectPOSIX,
			want:    true,
		},
		{
			name:    "falcon sensor disable now",
			command: `systemctl disable --now falcon-sensor`,
			dialect: DialectPOSIX,
			want:    true,
		},
		{
			name:    "sentinelone disable",
			command: `sudo /opt/sentinelone/bin/sentinelctl control disable`,
			dialect: DialectPOSIX,
			want:    true,
		},
		{
			name: "carbon black launch daemons",
			command: "sudo launchctl unload /Library/LaunchDaemons/com.carbonblack.daemon.plist\n" +
				"sudo launchctl unload /Library/LaunchDaemons/com.carbonblack.defense.daemon.plist",
			dialect: DialectPOSIX,
			want:    true,
		},
		{
			name:    "little snitch daemon",
			command: "sudo launchctl unload /Library/LaunchDaemons/at.obdev.littlesnitchd.plist",
			dialect: DialectPOSIX,
			want:    true,
		},
		{
			name:    "opendns updater only",
			command: "sudo launchctl unload /Library/LaunchDaemons/com.opendns.osx.RoamingClientConfigUpdater.plist",
			dialect: DialectPOSIX,
		},
		{
			name:    "dynamic falcon plists",
			command: "sudo launchctl unload #{falcond_plist}\nsudo launchctl unload #{userdaemon_plist}",
			dialect: DialectPOSIX,
		},
		{
			name:    "dynamic sysmon driver",
			command: "fltmc.exe unload #{sysmon_driver}",
			dialect: DialectPOSIX,
		},
		{
			name:    "sysmon uninstall",
			command: "sysmon -u",
			dialect: DialectPOSIX,
			want:    true,
		},
		{
			name:    "generic windows service",
			command: "net.exe stop #{service_name}\nsc.exe config #{service_name} start= disabled",
			dialect: DialectCMD,
		},
		{
			name:    "windefend stop disable and query",
			command: "sc stop WinDefend\nsc config WinDefend start=disabled\nsc query WinDefend",
			dialect: DialectCMD,
			want:    true,
		},
		{
			name:    "windefend native stop",
			command: `sc.exe stop WinDefend`,
			dialect: DialectPowerShell,
			want:    true,
		},
		{
			name:    "generic powershell service",
			command: "Stop-Service -Name #{service_name}\nRemove-Service -Name #{service_name}",
			dialect: DialectPowerShell,
		},
		{
			name:    "wrapped crowdstrike uninstall",
			command: `if (Test-Path "#{falcond_path}") {. "#{falcond_path}" /repair /uninstall /quiet } else { Get-ChildItem -Path "C:\ProgramData\Package Cache" -Include "WindowsSensor.exe" -Recurse | % { $sig=$(Get-AuthenticodeSignature -FilePath $_.FullName); if ($sig.Status -eq "Valid" -and $sig.SignerCertificate.DnsNameList -eq "CrowdStrike, Inc.") { . "$_" /repair /uninstall /quiet; break;}}}`,
			dialect: DialectPowerShell,
		},
	}

	accepted := 0
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: "/repo", DialectHint: test.dialect,
			})
			got := ExactEndpointSecurityProductDisable(facts)
			if got != test.want {
				t.Fatalf("proof=%t want=%t parse=%+v commands=%+v", got, test.want, facts.Parse, facts.Commands)
			}
			if got {
				accepted++
			}
		})
	}
	if accepted != 8 {
		t.Fatalf("accepted source candidates=%d want=8", accepted)
	}
}

func TestEndpointSecurityPowerShellCmdReader(t *testing.T) {
	input := Input{Tool: "shell", Command: `cmd /c sc stop WinDefend`, CWD: `C:\repo`, DialectHint: DialectPowerShell}
	facts := Analyze(input)
	if facts.Authoritative() {
		t.Fatal("the PowerShell reading of cmd /c is expected to be partial")
	}
	readings := HostScriptReadings(input, facts, 0, false)
	for _, twin := range readings.Twins {
		if twin.DialectHint == DialectCMD && ExactEndpointSecurityProductDisable(Analyze(twin)) {
			return
		}
	}
	t.Fatal("the shared command reader lost the exact CMD service call")
}

// TestWinDefendSequenceUnproved pins which calls leave a WinDefend stop to
// the closed sequence proof (rel-1-0-10:GAP-1194).
func TestWinDefendSequenceUnproved(t *testing.T) {
	cases := []struct {
		name, command      string
		dialect            Dialect
		unproved, stopOnly bool
	}{
		{name: "missing query", command: "sc stop WinDefend\nsc config WinDefend start=disabled", dialect: DialectCMD, unproved: true},
		{name: "extra command", command: "sc stop WinDefend\nsc config WinDefend start=disabled\nwhoami\nsc query WinDefend", dialect: DialectCMD, unproved: true},
		{name: "full sequence", command: "sc stop WinDefend\nsc config WinDefend start=disabled\nsc query WinDefend", dialect: DialectCMD},
		{name: "lone stop", command: `sc.exe stop WinDefend`, dialect: DialectPowerShell, stopOnly: true},
		{name: "sysmon then stop", command: `sysmon.exe -u; sc.exe stop WinDefend`, dialect: DialectPowerShell},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: tc.command, CWD: `C:\repo`, DialectHint: tc.dialect})
			if got := WinDefendSequenceUnproved(facts); got != tc.unproved {
				t.Errorf("WinDefendSequenceUnproved=%t want %t", got, tc.unproved)
			}
			if got := ExactWinDefendStopOnly(facts); got != tc.stopOnly {
				t.Errorf("ExactWinDefendStopOnly=%t want %t", got, tc.stopOnly)
			}
		})
	}
}

func TestExactEndpointSecurityProductDisableHardNegatives(t *testing.T) {
	tests := []struct {
		name    string
		command string
		dialect Dialect
	}{
		{name: "falcon stop only", command: `sudo systemctl stop falcon-sensor.service`, dialect: DialectPOSIX},
		{name: "falcon disable only", command: `sudo systemctl disable falcon-sensor.service`, dialect: DialectPOSIX},
		{name: "falcon disable now other service", command: `systemctl disable --now nginx`, dialect: DialectPOSIX},
		{name: "falcon disable now extra unit", command: `systemctl disable --now falcon-sensor nginx`, dialect: DialectPOSIX},
		{name: "falcon disable now variable", command: `systemctl disable --now "$UNIT"`, dialect: DialectPOSIX},
		{name: "falcon disable now glob", command: `systemctl disable --now 'falcon-*'`, dialect: DialectPOSIX},
		{name: "falcon disable now unrelated flag", command: `systemctl disable --now --force falcon-sensor`, dialect: DialectPOSIX},
		{name: "falcon disable now reordered flag", command: `systemctl --now disable falcon-sensor`, dialect: DialectPOSIX},
		{name: "falcon disable now conditional prefix", command: `test -f /tmp/maintenance && systemctl disable --now falcon-sensor`, dialect: DialectPOSIX},
		{name: "falcon disable now conditional suffix", command: `systemctl disable --now falcon-sensor || true`, dialect: DialectPOSIX},
		{name: "falcon disable now unknown product", command: `systemctl disable --now crowdstrike`, dialect: DialectPOSIX},
		{name: "sentinelone nearby path", command: `/tmp/sentinelctl control disable`, dialect: DialectPOSIX},
		{name: "sentinelone status", command: `/opt/sentinelone/bin/sentinelctl control status`, dialect: DialectPOSIX},
		{name: "sentinelone extra argument", command: `/opt/sentinelone/bin/sentinelctl control disable force`, dialect: DialectPOSIX},
		{name: "falcon wrong order", command: "sudo systemctl disable falcon-sensor.service\nsudo systemctl stop falcon-sensor.service", dialect: DialectPOSIX},
		{name: "falcon restore", command: "sudo systemctl stop falcon-sensor.service\nsudo systemctl enable falcon-sensor.service", dialect: DialectPOSIX},
		{name: "falcon extra target", command: "sudo systemctl stop falcon-sensor.service nginx\nsudo systemctl disable falcon-sensor.service", dialect: DialectPOSIX},
		{name: "falcon dynamic unit", command: "sudo systemctl stop $UNIT\nsudo systemctl disable $UNIT", dialect: DialectPOSIX},
		{name: "falcon conditional", command: "test -f /tmp/maintenance && sudo systemctl stop falcon-sensor.service\nsudo systemctl disable falcon-sensor.service", dialect: DialectPOSIX},
		{name: "falcon redirected", command: "sudo systemctl stop falcon-sensor.service 2>/dev/null\nsudo systemctl disable falcon-sensor.service", dialect: DialectPOSIX},
		{name: "carbon black one daemon", command: `sudo launchctl unload /Library/LaunchDaemons/com.carbonblack.daemon.plist`, dialect: DialectPOSIX},
		{name: "carbon black reverse order", command: "sudo launchctl unload /Library/LaunchDaemons/com.carbonblack.defense.daemon.plist\nsudo launchctl unload /Library/LaunchDaemons/com.carbonblack.daemon.plist", dialect: DialectPOSIX},
		{name: "carbon black nearby plist", command: "sudo launchctl unload /Library/LaunchDaemons/com.carbonblack.daemon.plist\nsudo launchctl unload /Library/LaunchDaemons/com.carbonblack.cloud.daemon.plist", dialect: DialectPOSIX},
		{name: "carbon black load", command: "sudo launchctl load /Library/LaunchDaemons/com.carbonblack.daemon.plist\nsudo launchctl load /Library/LaunchDaemons/com.carbonblack.defense.daemon.plist", dialect: DialectPOSIX},
		{name: "little snitch load", command: `sudo launchctl load /Library/LaunchDaemons/at.obdev.littlesnitchd.plist`, dialect: DialectPOSIX},
		{name: "little snitch extra command", command: "sudo launchctl unload /Library/LaunchDaemons/at.obdev.littlesnitchd.plist\nwhoami", dialect: DialectPOSIX},
		{name: "little snitch inert prose", command: `printf '%s\n' 'sudo launchctl unload /Library/LaunchDaemons/at.obdev.littlesnitchd.plist'`, dialect: DialectPOSIX},
		{name: "sysmon install", command: `sysmon -i`, dialect: DialectPOSIX},
		{name: "sysmon uninstall forced", command: `sysmon -u force`, dialect: DialectPOSIX},
		{name: "sysmon piped", command: `printf yes | sysmon -u`, dialect: DialectPOSIX},
		{name: "mdatp restore", command: `sudo mdatp config real-time-protection --value enabled`, dialect: DialectPOSIX},
		{name: "mdatp reordered", command: `sudo mdatp config real-time-protection disabled --value`, dialect: DialectPOSIX},
		{name: "mdatp extra option", command: `sudo mdatp config real-time-protection --value disabled --verbose`, dialect: DialectPOSIX},
		{name: "mdatp dynamic value", command: `sudo mdatp config real-time-protection --value "$STATE"`, dialect: DialectPOSIX},
		{name: "mdatp conditional", command: `test -f /tmp/maintenance && sudo mdatp config real-time-protection --value disabled`, dialect: DialectPOSIX},
		{name: "powershell sc alias", command: `sc stop WinDefend`, dialect: DialectPowerShell},
		{name: "windefend query only", command: `sc.exe query WinDefend`, dialect: DialectPowerShell},
		{name: "windefend missing query", command: "sc stop WinDefend\nsc config WinDefend start=disabled", dialect: DialectCMD},
		{name: "windefend restore", command: "sc stop WinDefend\nsc config WinDefend start=auto\nsc query WinDefend", dialect: DialectCMD},
		{name: "windefend extra command", command: "sc stop WinDefend\nsc config WinDefend start=disabled\nwhoami\nsc query WinDefend", dialect: DialectCMD},
		{name: "windefend other service", command: "sc stop Sense\nsc config Sense start=disabled\nsc query Sense", dialect: DialectCMD},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: "/repo", DialectHint: test.dialect,
			})
			if ExactEndpointSecurityProductDisable(facts) {
				t.Fatalf("unexpected proof: parse=%+v commands=%+v", facts.Parse, facts.Commands)
			}
		})
	}
}

func TestExactEndpointSecurityProductDisableFalconDisableNow(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{
			name:    "SecEBL literal unit",
			command: `systemctl disable --now falcon-sensor`,
		},
		{
			name:    "literal service unit",
			command: `systemctl disable --now falcon-sensor.service`,
		},
		{
			name:    "sudo literal unit",
			command: `sudo systemctl disable --now falcon-sensor`,
		},
		{
			name:    "sudo literal service unit",
			command: `sudo systemctl disable --now falcon-sensor.service`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: "/repo", DialectHint: DialectPOSIX,
			})
			if !ExactEndpointSecurityProductDisable(facts) {
				t.Fatalf("exact Falcon disable was not proved: parse=%+v commands=%+v", facts.Parse, facts.Commands)
			}
		})
	}
}

func TestExactEndpointSecurityProductDisableMDATPSourceCommand(t *testing.T) {
	const command = `sudo mdatp config real-time-protection --value disabled`
	facts := Analyze(Input{
		Tool: "shell", Command: command, CWD: "/repo", DialectHint: DialectPOSIX,
	})
	if !ExactEndpointSecurityProductDisable(facts) {
		t.Fatalf("exact source command was not proved: parse=%+v commands=%+v", facts.Parse, facts.Commands)
	}
}
