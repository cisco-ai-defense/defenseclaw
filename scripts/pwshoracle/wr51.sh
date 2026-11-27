#!/bin/bash
# wr51.sh: run the oracle dumper under Windows PowerShell 5.1 on the 5.1 sample. Launch through s7-winslot (it sets S7_WINHOST):
#   s7-winslot run --host auto --tag pwshoracle51 --wait-min 120 -- bash scripts/pwshoracle/wr51.sh <outdir>
# Parser only: the sample scripts are parsed, never run. Needs oracle-work/sample51.b64 (mk_sample51.py).
set -u -o pipefail
source ~/dc-eh/bin/dcenv >/dev/null 2>&1; export PATH=$HOME/dc-eh/bin:$HOME/bin:$PATH
WT=$HOME/dc-eh/wt/r111-det-pwsh-a; OUT=${1:-$HOME/dc-eh/jobs/pwshoracle51}; mkdir -p $OUT
H=${S7_WINHOST:-}; [ -n "$H" ] || { echo NO_WINHOST; exit 3; }
C="-F $HOME/dc-eh/ssh/config -o ControlMaster=no -o ControlPath=none -o ConnectTimeout=20"
cid=$(dc-claim start --host $H --agent claude:85a76cb2/det111-pwsh-oracle --task "PWSH oracle: Windows PowerShell 5.1 parse of 500 public sample rows (parser only, nothing executed; C:/Users/Public/pwshoracle51 removed after)" --lane det111-pwsh-oracle --shared 2>&1 | tail -1)
echo "CLAIM $cid"; case "$cid" in c-[0-9]*) ;; *) echo CLAIM_REFUSED; exit 5;; esac
D=C:/Users/Public/pwshoracle51
ssh -n $C $H "powershell -NoProfile -Command New-Item -ItemType Directory -Force -Path $D" >/dev/null 2>&1
if scp -q $C $WT/scripts/pwshoracle/PwshOracle.cs $WT/scripts/pwshoracle/pwsh_oracle_dump.ps1 $WT/oracle-work/sample51.b64 $H:$D/; then
  ssh -n $C $H "powershell -NoProfile -ExecutionPolicy Bypass -Command \"\$PSVersionTable.PSVersion.ToString()\"" 2>&1 | tr -d '\r' | tail -1 > $OUT/ps.version
  ssh -n $C $H "powershell -NoProfile -ExecutionPolicy Bypass -File $D/pwsh_oracle_dump.ps1 -InFile $D/sample51.b64 -OutFile $D/sample51.oracle51.jsonl" 2>&1 | tr -d '\r' | tail -5
  scp -q $C $H:$D/sample51.oracle51.jsonl $H:$D/sample51.oracle51.jsonl.version $OUT/ && echo FETCHED
else echo COPYFAIL; fi
ssh -n $C $H "powershell -NoProfile -Command Remove-Item -Recurse -Force $D -ErrorAction SilentlyContinue" >/dev/null 2>&1
dc-claim end $cid --result DONE --note "pwsh oracle 5.1 sample parsed; temp dir removed" 2>&1 | tail -1
echo "ps.version $(cat $OUT/ps.version)"; wc -l $OUT/sample51.oracle51.jsonl
echo WR51_DONE
