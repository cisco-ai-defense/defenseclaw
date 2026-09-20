// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestStructuredDirectoryCredentialAcquisition(t *testing.T) {
	t.Parallel()
	for _, input := range []Input{
		{Tool: "secretsdump", Args: json.RawMessage(`{"method":"dcsync","target":"dc01.example.test","username":"svc"}`)},
		{Tool: "secretsdump", Args: json.RawMessage(`{"method":"sam","target":"localhost","username":"CORP\\administrator"}`)},
		{Tool: "hashcat_crack", Args: json.RawMessage(`{"attack_mode":"dictionary","hash_file":"tickets.hash","hash_mode":13100,"wordlist":"words.txt"}`)},
		{Tool: "hashcat_crack", Args: json.RawMessage(`{"attack_mode":"rules","hash_file":"tickets.hash","hash_mode":13100}`)},
		{Tool: "kerberoast", Args: json.RawMessage(`{"domain":"example.test","target_user":"svc_sql"}`)},
	} {
		facts := Analyze(input)
		if !ExactDirectoryCredentialAcquisition(facts) {
			t.Fatalf("tool=%s missing structured credential-acquisition fact: %+v", input.Tool, facts)
		}
	}
}

func TestStructuredDirectoryCredentialAcquisitionSafeNegatives(t *testing.T) {
	t.Parallel()
	for _, input := range []Input{
		{Tool: "hashcat_crack", Args: json.RawMessage(`{"attack_mode":"show","hash_file":"tickets.hash","hash_mode":13100}`)},
		{Tool: "hashcat_crack", Args: json.RawMessage(`{"attack_mode":"dictionary","hash_file":"$HASH_FILE","hash_mode":13100}`)},
		{Tool: "hashcat_crack", Args: json.RawMessage(`{"attack_mode":"dictionary","hash_file":"tickets.hash","hash_mode":0}`)},
		{Tool: "kerberoast", Args: json.RawMessage(`{"domain":"$DOMAIN"}`)},
		{Tool: "kerberoast", Args: json.RawMessage(`{"domain":"example.test","extra":"x"}`)},
		{Tool: "secretsdump", Args: json.RawMessage(`{"method":"all","target":"dc01.example.test","username":"svc"}`)},
		{Tool: "secretsdump", Args: json.RawMessage(`{"method":"dcsync","target":"localhost","username":"svc"}`)},
	} {
		facts := Analyze(input)
		if ExactDirectoryCredentialAcquisition(facts) {
			t.Fatalf("tool=%s unexpectedly produced structured credential-acquisition fact: %+v", input.Tool, facts)
		}
	}
}

func TestDirectoryCredentialAcquisitionExactGrammars(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    DirectoryCredentialAcquisition
	}{
		{"secretsdump", "impacket-secretsdump -hashes aa:bb corp.example/Administrator@192.0.2.10 -just-dc-user Administrator", DirectoryCredentialSecretsDump},
		{"secretsdump script", "secretsdump.py -k -no-pass corp.example/user@dc.corp.example", DirectoryCredentialSecretsDump},
		{"local secretsdump", "impacket-secretsdump -sam SAM -system SYSTEM LOCAL", DirectoryCredentialSecretsDump},
		{"kerberoast", "impacket-GetUserSPNs -dc-ip 192.0.2.10 -request -request-user svc corp.example/user", DirectoryCredentialKerberoast},
		{"python kerberoast", "python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py corp.example/user -request", DirectoryCredentialKerberoast},
		{"asrep request", "impacket-GetNPUsers corp.example/user -no-pass -request -dc-ip 192.0.2.10", DirectoryCredentialASREPRoast},
		{"asrep output", "GetNPUsers.py corp.example/ -no-pass -usersfile users.txt -format hashcat -outputfile asrep.txt", DirectoryCredentialASREPRoast},
		{"kerberoast crack", "hashcat -m 13100 tickets.txt words.txt --force", DirectoryCredentialHashCrack},
		{"asrep crack", "hashcat --hash-type=18200 asrep.txt words.txt", DirectoryCredentialHashCrack},
		{"show recovered kerberos credential", "hashcat -m 13100 tickets.txt --show", DirectoryCredentialHashCrack},
		{"home relative hash inputs", "hashcat -m 13100 ~/tickets.txt ~/words.txt --force -O", DirectoryCredentialHashCrack},
		{"conditional acquisition remains detection evidence", "true && impacket-GetUserSPNs corp.example/user -request", DirectoryCredentialKerberoast},
		{"timeout wrapper", "timeout 120 impacket-secretsdump -k -no-pass corp.example/user@dc.example", DirectoryCredentialSecretsDump},
		{"hashcat mask attack", "hashcat -m 13100 ticket.hash -a 3 '?l?l?l?l?d?d'", DirectoryCredentialHashCrack},
		{"asrep output request", "impacket-GetNPUsers corp.example/ -usersfile users.txt -outputfile asrep.txt", DirectoryCredentialASREPRoast},
		{"netexec NTDS switch", "nxc smb dc.example -u administrator -H aa:bb --ntds", DirectoryCredentialSecretsDump},
		{"netexec NTDS module", "netexec smb dc.example -k --use-kcache -M ntdsutil", DirectoryCredentialSecretsDump},
		{"crackmapexec NTDS switch", "crackmapexec smb dc.example -u administrator -p password --ntds", DirectoryCredentialSecretsDump},
		{"john Kerberos crack", "john --wordlist=words.txt ticket.hash --format=krb5tgs", DirectoryCredentialHashCrack},
		{"john ASREP show", "john --show asrep.hash --format=krb5asrep", DirectoryCredentialHashCrack},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "execute_command", Command: test.command})
			if len(facts.DirectoryCredentialAcquisitions) != 1 ||
				facts.DirectoryCredentialAcquisitions[0].Operation != test.want ||
				!ExactDirectoryCredentialAcquisition(facts) {
				argv, argvOK := directoryCredentialStaticArgv(facts.Commands[0])
				operation, operationOK := exactDirectoryCredentialCommand(facts.Commands[0])
				t.Fatalf("acquisitions = %#v; parse = %#v; argv=%#v/%v hashcat=%v operation=%q/%v commands = %#v", facts.DirectoryCredentialAcquisitions, facts.Parse, argv, argvOK, exactKerberosHashcatCrack(argv[1:]), operation, operationOK, facts.Commands)
			}
			hasCredentialRead := false
			for _, command := range facts.Commands {
				hasCredentialRead = hasCredentialRead || hasFactOperation(command, OperationCredentialRead)
			}
			if !hasCredentialRead {
				t.Fatalf("commands = %#v", facts.Commands)
			}
		})
	}
}

func TestDirectoryCredentialAcquisitionHardNegatives(t *testing.T) {
	t.Parallel()
	commands := []string{
		"impacket-secretsdump --help",
		"impacket-secretsdump ${TARGET}",
		"impacket-GetUserSPNs -dc-ip 192.0.2.10 corp.example/user",
		"impacket-GetNPUsers corp.example/ -usersfile users.txt",
		"impacket-GetNPUsers corp.example/user -dc-ip 192.0.2.10",
		"hashcat -m 0 hashes.txt words.txt",
		"hashcat -m 0 hashes.txt --show",
		"hashcat -m 13100 tickets.txt",
		"nxc smb dc.example -u administrator -H aa:bb",
		"nxc smb dc.example -M spider_plus",
		"nxc smb dc.example --help --ntds",
		"john --wordlist=words.txt hashes.txt --format=raw-md5",
		"john ticket.hash --format=krb5tgs",
		"echo impacket-secretsdump corp.example/user@dc.example",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			facts := Analyze(Input{Tool: "execute_command", Command: command})
			if ExactDirectoryCredentialAcquisition(facts) || len(facts.DirectoryCredentialAcquisitions) != 0 {
				t.Fatalf("unexpected acquisitions %#v; parse = %#v", facts.DirectoryCredentialAcquisitions, facts.Parse)
			}
		})
	}
}

func TestDirectoryCredentialAcquisitionMultipleCommandsRemainDetected(t *testing.T) {
	t.Parallel()
	facts := Analyze(Input{Tool: "execute_command", Command: "impacket-secretsdump corp.example/user@dc1.example; impacket-secretsdump corp.example/user@dc2.example"})
	if len(facts.DirectoryCredentialAcquisitions) != 2 {
		t.Fatalf("acquisitions = %#v", facts.DirectoryCredentialAcquisitions)
	}
	if !ExactDirectoryCredentialAcquisition(facts) {
		t.Fatal("multiple exact acquisitions must remain detected")
	}
}
