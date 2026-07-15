# Native Windows CI certification

The `Windows Native CI` workflow is DefenseClaw's deterministic native Windows
x64 merge gate. It runs on pull requests, pushes to `main`, and manual dispatches
without provider secrets, WSL, MSYS, or Git Bash.

Repository branch protection must require the exact aggregate check name
`Windows Native Required`. Requiring individual matrix cell names is not a
substitute: the aggregate explicitly fails when any required job is failed,
cancelled, or skipped.

The gate certifies:

- explicit native Go DACL regressions, followed by the full Go suite, `go vet`,
  and native gateway/hook builds;
- every Python test, including the headless Textual TUI suite;
- a named native Local Splunk regression cell covering Docker/Compose
  argument arrays, Windows x64/Hyper-V/no-WSL preflight, ownership-aware ports,
  app packaging, secure credentials/DACLs, Web+HEC readiness, rollback,
  idempotency, owned-only disable, and packaged-wheel assets;
- explicit Windows Doctor checks for the registered Codex and Claude hook
  commands, including packaged post-setup tamper rejection, byte-for-byte
  recovery, and native-only repair guidance;
- PowerShell parsing, timeout/process-tree cleanup, redaction, and workflow
  contracts;
- a release-shaped Windows x64 gateway zip and Python wheel;
- a fresh install whose profile, application data, caches, connector homes,
  temp directories, DefenseClaw home, and PATH are disposable;
- an explicit `uv pip check`, managed-venv import provenance, installed CLI,
  doctor, skill/MCP scanner, and bounded headless-TUI smoke checks;
- gateway start/status/restart/stop behavior, stopped-status nonzero exit,
  reset idempotency, full uninstall, packaged reinstall, and cleanup; and
- required PowerShell contract cells for Codex and Claude Code covering setup,
  observe/action allow/block behavior, audit correlation, telemetry, bounded
  timeout handling, teardown, and cleanup.

The packaged artifact is built once and reused by the install/lifecycle and
connector jobs. Failure diagnostics are bounded, secret-redacted, retained for
five days, and followed by an unconditional isolated-process/listener/temp
cleanup step.

The pull-request gate remains secretless. Manual real-client cells in
`Connector Live E2E` are an alerting/regression radar and are not a fork-PR
merge gate. Production publication has a separate required Windows release
cell: it installs the exact Authenticode-signed Setup artifact, installs exact
official Codex and Claude Code versions, fails closed when either provider
credential is unavailable, and requires both connectors' live allow/block,
audit, and OTLP evidence, plus Codex automatic-trust evidence. `publish`
depends on that cell, and
the resulting `DefenseClawSetup-x64.exe.certification.json` is included in the
signed release checksum set. Its bounded three-hour job budget leaves time for
cleanup and failure-diagnostics upload after every bounded child operation. The
certification cell never builds or installs
DefenseClaw from the source checkout.

GitHub-hosted Windows runners do not provide the certified Docker Desktop
Linux-container/Hyper-V runtime. The deterministic merge gate mocks that
boundary; release acceptance must additionally run on a self-hosted native
Windows x64 machine. From PowerShell 7:

```powershell
docker.exe compose version
$Info = docker.exe info --format '{{json .}}' | ConvertFrom-Json
if ($Info.OSType -ne 'linux' -or $Info.OperatingSystem -notmatch 'Docker Desktop' -or $Info.KernelVersion -match 'microsoft|WSL') { throw 'Docker Desktop is not using the certified Linux-container/Hyper-V backend' }

$HomeDir = Join-Path $HOME '.defenseclaw'
$Stack = Join-Path $HomeDir 'splunk-bridge'
$Compose = Join-Path $Stack 'compose\docker-compose.local.yml'
$Credentials = Join-Path $Stack 'env\.env'
$Project = 'defenseclaw-splunk-local'
$ComposeArgs = @('compose', '--env-file', $Credentials, '--project-directory', $Stack, '--file', $Compose, '--project-name', $Project)

defenseclaw setup splunk --logs --accept-splunk-license --non-interactive
$Token = ((Get-Content -LiteralPath $Credentials | Where-Object { $_ -like 'DEFENSECLAW_HEC_TOKEN=*' }) -split '=', 2)[1]
if ((Invoke-WebRequest http://127.0.0.1:8000 -UseBasicParsing -MaximumRedirection 0).StatusCode -ne 200) { throw 'Splunk Web is not ready' }
if ((Invoke-WebRequest https://127.0.0.1:8088/services/collector/health -Headers @{ Authorization = "Splunk $Token" } -SkipCertificateCheck).StatusCode -ne 200) { throw 'Splunk HEC is not ready' }
if (Get-NetTCPConnection -State Listen -LocalPort 8000,8088 | Where-Object LocalAddress -ne '127.0.0.1') { throw 'Splunk listener escaped loopback' }

$DaclProblem = python -c "from defenseclaw.file_permissions import windows_acl_write_error; import sys; p=windows_acl_write_error(sys.argv[1]); print(p or '')" $Credentials
if ($LASTEXITCODE -ne 0 -or $DaclProblem) { throw "Unsafe credential DACL: $DaclProblem" }
$FirstHash = (Get-FileHash -LiteralPath $Credentials -Algorithm SHA256).Hash
$ExpectedVolumes = @('defenseclaw_splunk_local_etc', 'defenseclaw_splunk_local_var', 'defenseclaw_splunk_s3_exporter_state')
$VolumesBefore = @($ExpectedVolumes | ForEach-Object { & docker.exe volume inspect $_ --format '{{.Name}}' })
if (Compare-Object $ExpectedVolumes $VolumesBefore) { throw 'Owned Local Splunk volume identity mismatch' }

$AcceptanceId = [guid]::NewGuid().ToString()
$Payload = Join-Path $env:TEMP "defenseclaw-splunk-$AcceptanceId.json"
@{ actor='windows-native-acceptance'; action='config-update'; target_type='certification'; target_id=$AcceptanceId; after=@{ acceptance_id=$AcceptanceId }; severity='INFO' } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Payload -Encoding utf8
defenseclaw audit log-activity --payload-file $Payload
Start-Sleep -Seconds 8
$Search = "search index=defenseclaw_local acceptance_id=$AcceptanceId | head 1"
& docker.exe @ComposeArgs 'exec' '--no-TTY' '--user' 'splunk' 'splunk' '/opt/splunk/bin/splunk' 'search' $Search '-output' 'json'
if ($LASTEXITCODE -ne 0) { throw 'Generated DefenseClaw audit event was not found in Splunk' }

defenseclaw setup splunk --logs --accept-splunk-license --non-interactive
if ((Get-FileHash -LiteralPath $Credentials -Algorithm SHA256).Hash -ne $FirstHash) { throw 'Repeated setup changed credentials' }
$VolumesAfter = @($ExpectedVolumes | ForEach-Object { & docker.exe volume inspect $_ --format '{{.Name}}' })
if (Compare-Object $VolumesBefore $VolumesAfter) { throw 'Repeated setup changed owned volumes' }

defenseclaw setup splunk --disable --logs
if (& docker.exe ps --quiet --filter "label=com.docker.compose.project=$Project") { throw 'Owned containers still running after disable' }
foreach ($Volume in $VolumesBefore) { & docker.exe volume inspect $Volume *> $null; if ($LASTEXITCODE -ne 0) { throw "Owned volume was removed: $Volume" } }
Remove-Item -LiteralPath $Payload -Force
```

Run those commands from a wheel-installed profile whose repository, wheel,
temporary, profile, and data paths include spaces and Unicode. Preserve the
PowerShell transcript (redacting `$Token`); it is the release record for HEC
delivery, idempotent credential/volume identity, loopback binding, private DACL,
and owned-only disable with volume preservation.
