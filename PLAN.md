# PLAN — add a standalone Kali attack VM to the GOAD-Light lab

**Status: not executed** (for the attack VM). Written 2026-09-24, verified against kali.org and this
host, for later. Nothing below has been run: `~/vms/` does not exist and no Kali VM is registered.

*The SRV02 RAM half of this plan is done* — see "Already applied" at the end.

## Context

The GOAD-Light lab (dc01/dc02/srv02) is built and verified, but there is no dedicated attacker
machine. The only options today are the NixOS hypervisor host itself — reached over Tailscale
(MagicDNS enabled; tailnet peers include a phone and a machine offering an exit node), so running
Responder/mitm6/ntlmrelayx from it risks poisoning the link the user SSHes in over — or hand-rolled
`nix shell` tooling. GOAD ships no attack box: the idea exists only as an unimplemented TODO
(`docs/mkdocs/docs/changelog.md:72`, `- [ ] extension attackbox`).

Goal: a disposable, snapshottable Kali VM on the lab subnet with internet access, wired **outside**
Vagrant and outside `goad.py`'s lifecycle — `./goad.sh start|stop|destroy` must never touch it.

Decided: Kali's **official prebuilt VirtualBox image** (not ISO, not container, not Vagrant),
static **192.168.56.30** (vboxnet0's DHCP pool is .101–.254, dhcpd at .100), DNS at
**192.168.56.10**, NIC1 NAT + NIC2 host-only, 2048 MB / 2 vCPU with XFCE kept.

Out the window: this VM is deliberately *not* a GOAD extension and not in the lab's `boxes` array,
so it never boots with `goad.sh` and never appears in `vagrant status`.

## Steps

### 1. Download and extract

```bash
mkdir -p ~/vms/kali && cd ~/vms/kali
curl -LO https://cdimage.kali.org/kali-2026.2/kali-linux-2026.2-virtualbox-amd64.7z   # 302s → kali.download, -L needed
sha256sum kali-linux-2026.2-virtualbox-amd64.7z
# expect 41ed7ec51cdd3a5ca663ec09492261ba81acb26625fdda85ce7acb16909f3cee   (3.65 GiB)
7z x kali-linux-2026.2-virtualbox-amd64.7z
ls -la ~/vms/kali/kali-linux-2026.2-virtualbox-amd64/
```

Current release is **2026.2** (`kali-linux-2026.2-virtualbox-amd64.7z`); weekly builds are
`kali-linux-2026-W39-…`. The archive is 7z, **not an OVA** — it holds a `.vbox` + `.vdi` pair, and
the `.vbox` references the `.vdi` by *relative* path, so keep them in the same directory and never
move the `.vdi` alone. Confirm from the `ls` (do not guess): the `.vbox` filename, the
`<Machine name=…>` that becomes the registered VM name, and whether the `.vbox` has a
`<DVDImages>` entry pointing at `VBoxGuestAdditions.iso` — this host has no
`/usr/share/virtualbox/VBoxGuestAdditions.iso`, so if the entry exists, registration fails with
*"Cannot register the DVD image … already exists"* (`E_INVALIDARG`). Workaround: delete the
`<Image … VBoxGuestAdditions.iso"/>` line inside `<DVDImages>…</DVDImages>` (plain XML) before
registering. Guest Additions themselves are already installed inside the image — unrelated.

### 2. Register and wire it (no Vagrant)

```bash
VBoxManage registervm ~/vms/kali/kali-linux-2026.2-virtualbox-amd64/<name>.vbox   # registers in place
VBoxManage list vms                                                                # take the name verbatim
VBoxManage modifyvm "<VM name>" \
  --groups "/LAB" --memory 2048 --cpus 2 --vram 128 --audio-enabled off --rtc-use-utc on \
  --nic1 nat --nic-type1 82540EM \
  --nic2 hostonly --host-only-adapter2 vboxnet0 --nic-type2 82540EM --cable-connected2 on
VBoxManage showvminfo "<VM name>" | grep -E "Name|Groups|Memory size|Number of CPUs|NIC 1|NIC 2"
```

All of this needs the VM powered off (it is, right after `registervm`). `--groups "/LAB"` keeps it
separate from the lab's `/GOAD` group; the group appears on demand. Optional rename to something
self-describing (rewrites the `.vbox` in place, relative disk path stays valid):
`VBoxManage modifyvm "<VM name>" --name "Kali-Attack"`.

### 3. Boot and configure the guest network

```bash
VBoxManage startvm "<VM name>" --type gui        # or --type headless (host has DISPLAY=:0 anyway)
```

In the guest: expect **`enp0s3`** = NAT, **`enp0s8`** = host-only (names follow the PCI slot, so
they hold for both `82540EM` and virtio — but confirm with `ip -br link` / `nmcli device status`).
The profile *names* must be read from `nmcli -t -f NAME,DEVICE con show`, not guessed.

```bash
# host-only NIC → static .30 with the DC as resolver (no gateway: internet stays on the NAT NIC)
sudo nmcli con mod "<host-only profile>" ipv4.method manual ipv4.addresses 192.168.56.30/24 \
  ipv4.dns 192.168.56.10 ipv4.dns-search sevenkingdoms.local ipv6.method disabled
sudo nmcli con up "<host-only profile>"
# …or if no profile exists yet:
sudo nmcli con add type ethernet con-name lab-hostonly ifname enp0s8 \
  ipv4.method manual ipv4.addresses 192.168.56.30/24 \
  ipv4.dns 192.168.56.10 ipv4.dns-search sevenkingdoms.local ipv6.method disabled

# NAT NIC: refuse DHCP-supplied DNS (VirtualBox NAT leaks the host's Tailscale MagicDNS)
NAT="$(nmcli -t -g NAME,DEVICE con show | awk -F: '$2=="enp0s3"{print $1}')"
sudo nmcli con mod "$NAT" ipv4.ignore-auto-dns yes ipv6.ignore-auto-dns yes && sudo nmcli con up "$NAT"

cat /etc/resolv.conf       # want nameserver 192.168.56.10 — NOT 100.100.100.100 / tail801926.ts.net
```

Do not hand-edit `/etc/resolv.conf` (NetworkManager owns it). **No `/etc/hosts` entries needed** —
dc01 is authoritative for both zones and forwards to 1.1.1.1, verified from this host:
`sevenkingdoms.local` → .10, `north.sevenkingdoms.local` → .11, `winterfell…` → .11, `google.com` →
public A record. `/etc/krb5.conf` is also unnecessary for impacket/`nxc` (they take `-dc-ip`); add it
only if `kinit` or `nxc -k` is wanted. Clock: Guest Additions' time sync is running and the host is
NTP-synced, so Kerberos skew should not bite — check `timedatectl`; fallback
`sudo systemctl enable --now systemd-timesyncd`.

Then, **from a clean shutdown** (`sudo poweroff`) so the snapshot carries the network config:

```bash
VBoxManage snapshot "<VM name>" take "configured-clean" --description "kali 2026.2, static .30, DNS .10"
# restore later: VBoxManage snapshot "<VM name>" restore "configured-clean"
# headless switch if RAM gets tight: sudo systemctl set-default multi-user.target
```

### 4. Repo/doc changes

- `workspace/432917-goad-light-virtualbox/provider/Vagrantfile` — done (see below).
- `LAB-SETUP.md` — new section for the attack VM (image URL/sha256, steps 2–3, snapshot, the
  start/stop commands, verification); plus: attacker row in the §1 topology table marked as *not*
  Vagrant-managed, a §2 line that it is operated with `VBoxManage` rather than `goad.sh`, and a
  §4.4 line that the same NAT-DNS leak is fixed inside Kali with `ipv4.ignore-auto-dns yes`.

## Verification

1. Host → guest: `ping -c2 192.168.56.30`; in-guest: `ping -c2 192.168.56.1` and `.10`.
2. DNS is the *designed* path, not just any resolver: `nslookup winterfell.north.sevenkingdoms.local`
   → .11 and `nslookup google.com` → public A record.
3. Kerberos port + clock in one shot: `nmap -Pn -sV -p88 192.168.56.11` → `88/tcp open kerberos-sec
   Microsoft Windows Kerberos (server time: …)`; compare against `date -u`.
4. `nxc smb 192.168.56.0/24` (crackmapexec is gone from Kali) → exactly three hits:
   `DC01`/`sevenkingdoms.local`, `DC02`/`sevenkingdoms.local`, `SRV02`/`north.sevenkingdoms.local`.
5. Real AD proof: `impacket-GetNPUsers north.sevenkingdoms.local/brandon.stark -no-pass -dc-ip
   192.168.56.11 -format hashcat` → `$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:…`
   (`brandon.stark` has `DoesNotRequirePreAuth` in `ad/GOAD-Light/data/config.json`). Optional
   crack to prove it: `sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz && hashcat -m 18200 -a 0 …`
6. Lab untouched: `./goad.sh -i 432917-goad-light-virtualbox -t status` still lists exactly three
   machines and never the Kali VM.

## Risks / notes

- **RAM is the real constraint.** The three lab VMs alone are 2048+2048+3072 = 7 GB of the host's
  13.6 GB, which was already ~11 GB used / 4.8 GB swap before any of this. A fourth 2048 MB guest
  (plus VBox overhead plus XFCE) is oversubscription: expect swap, and watch for the kernel OOM
  killer that ended the original provisioning run. Mitigations, cheapest first: boot Kali only when
  attacking and shut it down after; use `--type headless` / `systemctl set-default multi-user.target`
  (saves the X session, all tooling is CLI); drop to `--memory 1536` if XFCE still behaves; the lab
  itself is unaffected either way (host-only is a separate virtual switch). Do **not** raise SRV02
  back to 4096 to compensate.
- **Sandbox.** VirtualBox state changes are silently discarded inside the Bash sandbox, and
  `VBoxManage`/`vagrant` state queries then lie (`list runningvms` empty while VMs run;
  `modifyvm` appearing to succeed without writing the `.vbox`). Run every `VBoxManage`/`vagrant`
  command with the sandbox disabled.
- **Tailscale.** The lab subnet is reached over the direct `vboxnet0` route; confirm with
  `ip route get 192.168.56.30`. Only if a tailnet subnet router ever advertises 192.168.56.0/24
  would lab traffic get attracted away. Never fix the DNS leak by disabling Tailscale.
- The prebuilt image is an 80 GB *dynamic* VDI (~15 GB extracted); expect ~10–15 GB of real disk.
- `kali`/`kali` is fine behind NAT, but change it (`passwd`) before ever adding a bridged adapter or
  a forwarded port.
- Tools present in the image: impacket scripts, `nxc`, `responder`, `hashcat`, `john`, `certipy-ad`,
  `nmap`. Missing by default: `kerbrute`, `mitm6`, `kinit` — `sudo apt install …` over the NAT NIC.
- Not covered (see LAB-SETUP.md): SSMS still parked, dc02 still advertises NAT-adapter DNS records,
  `child_domain` re-promotion guard unpatched.

## Already applied — SRV02 RAM (2026-09-24)

- `ad/GOAD-Light/providers/virtualbox/Vagrantfile` and the live
  `workspace/432917-goad-light-virtualbox/provider/Vagrantfile`: SRV02 4096 → **3072**.
- `VBoxManage modifyvm GOAD-Light-SRV02 --memory 3072` with the VM powered off, so the config
  itself (`GOAD-Light-SRV02.vbox`, `RAMSize`) now reads 3072.
- All three VMs were gracefully halted and restarted headless; verified with
  `VBoxManage showvminfo … --machinereadable | grep memory` → `memory=3072`.
- Why the Vagrantfile matters: Vagrant re-applies `v.memory` on every boot
  (`plugins/providers/virtualbox/config.rb:126` → `customize("pre-boot", ["modifyvm", :id, "--memory", …])`,
  run by `action.rb`'s boot path), so an un-edited live copy would silently restore 4096.
