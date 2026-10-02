# GOAD-Light — local lab: setup, state and caveats

Deployment notes for the GOAD-Light instance running on this host. Build finished
**2026-09-24**; every playbook in `playbooks.yml`'s `default:` list has run green and the
vulnerability markers were verified live over WinRM.

Not part of upstream GOAD — this file is host/deployment-specific.

---

## 1. What is deployed

| VM | Hostname | Domain | IP (host-only) | Role / services |
|----|----------|--------|----------------|-----------------|
| `GOAD-Light-DC01` | kingslanding | sevenkingdoms.local (parent, NETBIOS `SEVENKINGDOMS`) | 192.168.56.10 | DC, DNS, ADCS (CA running), firewall off (Domain) |
| `GOAD-Light-DC02` | winterfell | north.sevenkingdoms.local (child, NETBIOS `NORTH`) | 192.168.56.11 | DC, DNS (child zone + parent + `_msdcs`) |
| `GOAD-Light-SRV02` | castelblack | north.sevenkingdoms.local | 192.168.56.22 | Member server: MSSQL `SQLEXPRESS` (1433), IIS + default site, WebDAV, shares `all` / `public` |

- Instance ID: **`432917-goad-light-virtualbox`**, provider VirtualBox, IP range `192.168.56.x`.
- Working copy: `workspace/432917-goad-light-virtualbox/` (provider dir `…/provider`, the Vagrantfile lives there).
- Two NICs per VM: NAT (`10.0.2.15`, DHCP, internet) + host-only (domain traffic). See §5.1.
- Box: `StefanScherer/windows_2019` `2021.05.15`, 2 vCPU each. RAM: dc01/dc02 **2048 MB**, srv02 **3072 MB** (lowered from upstream 3000/3000/6000 — see §4.6).
- Extensions (elk, exchange, guacamole, lx01, ws01, wazuh): **not installed**, they were never requested.
- Playbook chain that ran: `build → ad-servers → ad-parent_domain → ad-child_domain → wait5m → ad-members → ad-trusts → ad-data → ad-gmsa → laps → ad-relations → adcs → ad-acl → servers → security → vulnerabilities`. `ad-trusts`, `ad-gmsa`, `laps` are no-ops for GOAD-Light (empty groups in `ad/GOAD-Light/data/inventory`).

All three VMs run headless; the state lives on disk in `~/VirtualBox VMs/GOAD/`.

---

## 2. Operating the lab

```bash
cd /home/veryloooong/Repos/GOAD

./goad.sh -i 432917-goad-light-virtualbox -t status   # vagrant status
./goad.sh -i 432917-goad-light-virtualbox -t start    # power on all 3
./goad.sh -i 432917-goad-light-virtualbox -t stop
./goad.sh -i 432917-goad-light-virtualbox -t destroy  # nuke and start over
./goad.sh -h                                          # full task list (install/provision/snapshot/…)
```

Note: goad's instance table shows this lab as `ready for provision` even though the build is
finished — trust the `vagrant status` output that the same command prints at the end.

`goad.sh` drives `~/.goad/.venv` (see §5.5 — that venv is the fragile part). Playbooks can also be
run by hand from the instance's `ansible/` dir:

```bash
cd workspace/432917-goad-light-virtualbox/ansible
ansible-playbook playbooks/servers.yml --limit srv02
```

Access / credentials — the source of truth is `ad/GOAD-Light/data/config.json`:

| What | Value |
|------|-------|
| WinRM (all 3 VMs) | `http://192.168.56.1x:5985` — user `vagrant` / `vagrant` |
| Parent domain admin | `sevenkingdoms\administrator` = `domain_password` of `sevenkingdoms.local` in config.json |
| Child domain admin | `north\administrator` = `domain_password` of `north.sevenkingdoms.local` |
| Local admin (per VM) | `local_admin_password` in config.json |
| RDP | `vagrant`/`vagrant`, or the domain users listed under `local_groups` |

Every lab user's password is in `config.json` under `domains.<domain>.users`.

### Re-checking that the lab is the intended build

The markers that prove the vulnerable configuration is really applied (all confirmed on 2026-09-24):

```bash
~/.goad/.venv/bin/python - <<'PY'
import winrm
def ps(ip, cmd):
    s = winrm.Session(f'http://{ip}:5985/wsman', auth=('vagrant','vagrant'), transport='ntlm')
    return s.run_ps(cmd).std_out.decode().strip()

print('dc01 users :', ps('192.168.56.10', '(Get-ADUser -Filter *).Count'))          # 16
print('dc02 users :', ps('192.168.56.11', '(Get-ADUser -Filter *).Count'))          # 17
print('srv02 sql  :', ps('192.168.56.22', "(Get-Service 'MSSQL$SQLEXPRESS').Status")) # Running
PY
```

`vagrant`/`vagrant` is accepted over WinRM on all three VMs (that is what the inventory uses).

Individual checks worth running after any change:

- **dc01**: 16 users; `certutil -CAInfo` → CA running; `Get-NetFirewallProfile` → Domain `False`.
- **dc02**: 17 users; `brandon.stark` has `DoesNotRequirePreAuth` (AS-REP roastable); SPNs on `sansa.stark` (`HTTP/eyrie…`), `jon.snow` (`HTTP/thewall…`), `sql_svc` (`MSSQLSvc/castelblack…`) → kerberoastable; `krbtgt` present for golden-ticket work.
- **srv02**: `Get-Service 'MSSQL$SQLEXPRESS'` + `WMI`/IIS `Running`, WebDAV feature `Installed`, `Get-SmbShare` shows `all`, `public`, `C$`…; `sql_svc` login has IMPERSONATE paths from `config.json`.

---

## 3. Uncommitted changes in this repo (all local, none upstream)

`git status` — 4 modified files, all deliberate, plus scratch logs:

| File | Change | Why |
|------|--------|-----|
| `ansible/roles/child_domain/tasks/main.yml` | +6: `Set-NetIPInterface -InterfaceAlias <domain_adapter> -InterfaceMetric 10` | `member_server`/`commonwkstn` already had it, `child_domain` had it commented out. Without it the NAT NIC wins the DNS lookup order on the *promoting* DC. |
| `ansible/roles/mssql/defaults/main.yml` | `download_url_2019` → `https://go.microsoft.com/fwlink/?linkid=866658` | the old `download.microsoft.com/download/7/f/8/7f8a9c43-…` guid URL is dead (404). |
| `ansible/roles/mssql/tasks/main.yml` | config file rendered **on the controller** (`win_copy` + `lookup('template')`), CRLF/Jinja-header normalisation, then download → extract → `setup.exe` from the extracted media | two separate breakages: (a) `win_template` silently doesn't render under the installed collection versions (§5.5); (b) the SSEI bootstrap rejects `ConfigurationFile` ("Index was outside the bounds of the array"), only the media `setup.exe` accepts it. |
| `ad/GOAD-Light/data/inventory` | `[mssql_ssms]` → `;srv02` + comment | SSMS role is broken against the current download (§5.2). |
| `ad/GOAD-Light/providers/{virtualbox,vmware}/Vagrantfile` | RAM 3000/3000/6000 → **2048/2048/3072** | host has 13 GB total; the original sizing OOM-killed the provisioning run. The *live* copy of this file is `workspace/432917-goad-light-virtualbox/provider/Vagrantfile` (untracked, not regenerated by `goad.sh start|stop|status`) — keep the two in sync. |
| `.gitignore` | +devenv/direnv/pre-commit entries | user's own, unrelated to the lab. |

Scratch output (untracked, safe to delete): `goad.log`, `output.log`, `nmap.log`,
`provision-*.log` (the re-run transcripts, incl. `provision-rest7.log` = final passing chain).

---

## 4. Caveats / known deviations from "the intended lab"

### 4.1 SSMS is not installed (only real gap)
`ansible/roles/mssql_ssms/tasks/main.yml` downloads `https://aka.ms/ssmsfullsetup`, which now
serves **SSMS 22** (a VS 2022 bootstrapper), but drives it with SSMS-18 switches
(`/install /quiet /norestart`) and then checks for `C:\Program Files (x86)\Microsoft SQL Server
Management Studio 18`. Result: the bootstrapper falls back to interactive and hangs forever.
Impact: GUI only — every GOAD-Light SQL attack path (impersonate, `xp_cmdshell`, `sql_svc`
kerberoast) works with `sqlcmd`, Impacket, or mssqlclient.py. Parked via `[mssql_ssms]`.
Fix when wanted: modern switches (`--quiet --wait --norestart`) **and** a version-agnostic
install check (glob `C:\Program Files (x86)\Microsoft SQL Server Management Studio*` or a
registry query) — then re-add `srv02` to `[mssql_ssms]` and run `servers.yml --limit srv02`.

### 4.2 dc02 advertises unreachable addresses in AD DNS
Because the NAT adapter also registers in DNS, dc02's own records include `A 10.0.2.15` and
several `AAAA` entries (including a Tailscale `fd17:…` address). Harmless for host-only attacks,
but resolution from the guests can pick a wrong address. Not cleaned yet. To inspect/remove
(run on dc02, after confirming with the first command that you are only deleting NAT-adapter data):

```powershell
Get-DnsServerResourceRecord -ZoneName north.sevenkingdoms.local -Name winterfell -RRType A
Get-DnsServerResourceRecord -ZoneName north.sevenkingdoms.local -Name winterfell -RRType Aaaa
# Remove-DnsServerResourceRecord -ZoneName north.sevenkingdoms.local -Name winterfell -RRType Aaaa -Force
```

Keep `192.168.56.11` — delete only the `10.0.2.15` / IPv6 entries.

### 4.3 The `child_domain` re-promotion trap is still there
`ansible/roles/child_domain/tasks/main.yml` decides whether to promote using
`Get-ADDomain -Identity $NewDomainName`, i.e. **over DNS**. Right after a promotion, or while a
DC's own DNS is still settling, that throws `ADIdentityNotFoundException` on a machine that *is*
already a DC → the role runs `Install-ADDSDomain` again on live AD DS → Directory Service event
**2542** ("database has been replaced"), NTDS disabled, no `C:\Windows\NTDS`. That is exactly what
killed the first build and forced the dc02 rebuild.

**Never re-run `ad-child_domain.yml` against a machine that is already a DC** unless you have
checked locally first. Robust guard to patch in (local state, no DNS):

```powershell
$cs = Get-CimInstance Win32_ComputerSystem
$domainExist = $cs.PartOfDomain -and ($cs.Domain -eq $NewDomainName)
```

### 4.4 Tailscale must stay up, so the NAT-DNS workaround must stay in place
Tailscale is required (it's how this host is reached), but its MagicDNS resolver
(`100.100.100.100`, `0.100.100.100`) and search suffix `tail801926.ts.net` leak into the guests
through the VirtualBox NAT DHCP, and outrank the domain DNS — which breaks promotion and joins
(`Error value: 8524 … DNS lookup failure`, event 1125). Handled guest-side, Tailscale untouched:

- host-only NIC: `InterfaceMetric 10` (now also in the `child_domain` role, §3);
- NAT NIC: `RegisterThisConnectionsAddress $False`, DNS pinned to a DC (`192.168.56.10` on
  dc01/dc02, `192.168.56.10`/`10.0.2.3` on srv02) — per GOAD issue #439.

If a VM is ever rebuilt or its network reset, redo this before running any AD playbook.

### 4.5 Toolchain drift (the root cause of most of the weirdness)
`~/.goad/.venv` runs **Python 3.14.7** (the only interpreter on PATH, from nix). GOAD pins
`ansible-core==2.18.0` (py 3.11–3.13 only) and `ansible.windows==1.11.0` /
`community.windows==1.11.0`; on 3.14 pip resolves **ansible-core 2.21.4** + ansible 14.4.0, and
`ansible-galaxy collection list` shows two copies of each collection (`~/.ansible/collections`
plus the nix bundle). Consequence: `ansible.windows.win_template` **copies templates verbatim** —
no `{{ }}` substitution — which produces unrelated-looking failures far downstream. Three roles
use `win_template` (`mssql`, `sccm/install/mecm`, `logs_windows`); only `mssql` was hit here and
worked around.

### 4.6 Memory
Host has 13 GB. Guests peak hard during AD promotion + SQL install. 2048 MB per DC is usable but
tight; do **not** go below it. srv02 was dropped from 4096 to **3072 MB** and power-cycled on
2026-09-24 — applied in the repo template, the live instance Vagrantfile, and the VM config itself
(`VBoxManage modifyvm … --memory 3072`), so nothing can silently put it back. Vagrant re-applies
`v.memory` from the Vagrantfile on every boot (`plugins/providers/virtualbox/config.rb` →
`customize("pre-boot", ["modifyvm", :id, "--memory", …])`), which is why the live copy of that file
must stay in sync. The earlier failure mode was the kernel OOM-killing the ansible run.

### 4.7 VirtualBox commands must run outside the Bash sandbox
Sandboxed shell calls silently discard VirtualBox state changes and misreport machine state: a
`VBoxManage modifyvm --memory 3072` appeared to succeed but never rewrote
`GOAD-Light-SRV02.vbox`, and `VBoxManage list runningvms`/`vagrant status` reported `poweroff` for
all three VMs while they were running. Always run `VBoxManage` and `vagrant` with the sandbox
disabled, and confirm with `VBoxManage showvminfo … --machinereadable | grep memory`.

### 4.8 Upstream URLs rot
Both MSSQL download URLs and the SSMS one have moved at least once. Symptom pattern: a role
"works" upstream but 404s or silently changes behaviour here. Fixes live in §3 and §4.1; if a
fresh clone is used instead of this working tree, re-apply them.

---

## 5. Rebuilding a clean, close-to-intended environment

If this working tree is lost (or you want a lab that matches upstream pins exactly):

1. **Interpreter first.** Build the venv on Python 3.12/3.13, not 3.14 —
   `nix shell nixpkgs#python312` then `python -m venv ~/.goad/.venv`. Base it on
   `requirements_311.yml` (or `pyproject.toml`) so `ansible-core==2.18.0` is actually installable.
2. **Collections at the pinned versions.** `ansible-galaxy install -r ansible/requirements.yml --force`,
   then verify: `ansible-galaxy collection list` must show **one** version of `ansible.windows`
   (1.11.0) — duplicates mean the nix `ansible` bundle leaked into `PATH`. Keep the nix bundle out
   of lab shells.
3. **Patches.** Apply the four §3 edits (or a fresh clone will re-hit the dead SQL URL, the
   `win_template` no-op, and the missing metric in `child_domain`).
4. **RAM.** Keep dc01/dc02 ≥ 2048 and srv02 ≥ 3072 in the Vagrantfile before creating the VMs.
5. **Order matters.** On a fresh VM, always start at `build.yml` (it upgrades PowerShellGet, which
   `win_psmodule --AcceptLicense` needs) and follow the `default:` list in order. Resuming at
   `ad-child_domain.yml` on a fresh box fails with `Exit code 94` (blank local Administrator
   password) and no DNS role.
6. **Tailscale.** Leave it running and apply the §4.4 network workaround right after the Vagrant
   boxes come up, before `ad-parent_domain.yml`.
7. Then: `./goad.sh -i <instance> -t install` (or the provision task) and let the whole list run
   without interrupts. Budget for the run being long — `wait5m` is literal, and the SQL install
   adds ~15–25 min.

Verification after the rebuild is the §2 checklist.

---

## 6. Suggested next steps (none applied)

1. Clean dc02's DNS records (§4.2).
2. Patch the `child_domain` guard (§4.3) so a re-run can never corrupt a DC again.
3. Restore SSMS with modern flags + version-agnostic check (§4.1), then re-add `srv02` to
   `[mssql_ssms]`.
4. Optional, if you want the working tree clean: fold §3 into a branch/commit.
