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
	if accepted != 5 {
		t.Fatalf("accepted source candidates=%d want=5", accepted)
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
		{name: "windefend stop only", command: `sc stop WinDefend`, dialect: DialectCMD},
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

func TestExactEndpointSecurityProductDisableMDATPSourceCommand(t *testing.T) {
	const command = `sudo mdatp config real-time-protection --value disabled`
	facts := Analyze(Input{
		Tool: "shell", Command: command, CWD: "/repo", DialectHint: DialectPOSIX,
	})
	if !ExactEndpointSecurityProductDisable(facts) {
		t.Fatalf("exact source command was not proved: parse=%+v commands=%+v", facts.Parse, facts.Commands)
	}
}
