# Active Directory protection

This opt-in guardrail profile extends the embedded balanced defaults and blocks
the directory credential attacks and bulk directory enumeration that an agent
would run against a managed Windows domain. Assign it only to connectors on
hosts that are, or can reach, a production Active Directory domain; a domain
name is never treated as authorization evidence.

The v1 block claim covers, on a complete static invocation:

- **Kerberos ticket requests for offline cracking** — `impacket-GetUserSPNs
  -request` (Kerberoasting) and `impacket-GetNPUsers` (AS-REP roasting). The
  built-in default pack alerts on these (strict blocks them); this pack blocks
  them in every profile.
- **Export of the directory credential database** — `ntdsutil` Install-From-Media
  (`ifm ... create full`). The built-in default pack only alerts on these.
- **Credential use against a domain service** — NetExec / CrackMapExec
  (`nxc`, `netexec`, `crackmapexec`) authenticating to `smb`, `ldap`, `mssql`,
  `winrm`, `wmi`, `rdp`, `ssh`, `ftp`, `vnc`, `nfs` or `smtp` with a password
  (`-p`/`--password`), an NT or LM:NT hash (`-H`/`--hash`/`--hashes`), a Kerberos
  ticket cache (`--use-kcache`), or empty (anonymous) credentials, in any
  argument order. The built-in default pack alerts on this (strict blocks it);
  this pack blocks it. DefenseClaw does not decode the credential value, so a
  dynamic (`$VAR`, command-substituted) credential or target is not blocked.
- **Bulk directory collection for attack-path mapping** — a NetExec `ldap`
  run with a BloodHound or mass-enumeration module (`--bloodhound`, `--users`,
  `--groups`, `--kerberoasting`, `--asreproast`).
- **Password spraying** — a NetExec run whose user or password set is a
  wordlist file (`.txt`/`.lst`), against one or many domain hosts.

Directory replication / secrets dumps (`impacket-secretsdump`, DCSync,
`nxc --ntds`, offline `hashcat`/`john` of Kerberos hashes) are already blocked
by the embedded balanced defaults, so this pack does not re-ship them.

## Trade-offs when the pack is on

- A host with the pack on cannot promote a domain controller from media with
  `ntdsutil ... ifm ... create full` (a full NTDS database export), nor read an
  NTDS copy with those tools. Legitimate IFM media creation must run on a host
  without the pack. `create sysvol full` and RODC media are not blocked.
- Blocking a Kerberos ticket **request** trades away the returned-ticket
  (`credential.returned_kerberos_tgs`) detection for prevention: the request is
  stopped, so there is no returned TGS to observe. The built-in default keeps
  the request at an alert precisely so that result can still be seen.

## What this pack deliberately does not cover

Ordinary directory administration stays allowed with the pack on, including a
single-user LDAP lookup, `klist`, joining a domain (`net ads join`), a
single-account `Get-ADUser`, and a single-object `dsquery`.

The pack does not block (it may still alert where another rule detects):

- Standalone collectors and spray tools other than NetExec — `SharpHound.exe`,
  `bloodhound-python`, and `kerbrute`. Their operand grammar is not parsed to a
  complete, authoritative action, so a match cannot authorize a block.
- Kerberos ticket **use** (pass-the-ticket / overpass-the-hash) as distinct
  from a ticket **request**.
- Broad `ldapsearch` enumeration with a raw, unquoted LDAP filter, whose shell
  parse is not complete.
- Dynamic operands (globs, command substitution, variables) in any of the
  covered commands, and help, version, or dry-run forms.
