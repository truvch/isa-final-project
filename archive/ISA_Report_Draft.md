# Ubuntu Desktop System Hardening Report

**Course:** Information Security and Assurance 1  
**Members:** Aaron [add full name] and [partner name]  
**Section:** [add section]  
**Implementation date for controls 1–8:** 6 October 2026  
**Status:** Draft — eight categories implemented; partner sections and some screenshot evidence remain to be added.

## 1 Introduction

For this project, we installed Ubuntu Desktop in a virtual machine, examined its initial configuration, and applied security controls using the supplied CIS Ubuntu Linux 26.04 LTS Benchmark v1.0.0 [1]. The objective was to reduce unnecessary exposure, restrict access to sensitive functions, and establish safer defaults while keeping the desktop usable.

I completed the first eight control categories. My partner will complete the remaining seven categories. Following the project instructions, related settings are grouped together: several changes to file permissions, for example, count as one category rather than several controls. This report covers selected benchmark recommendations; it does not claim complete CIS profile compliance.

## 2 Laboratory Environment and Method

We used a Google Cloud host to provide remote access to a shared KVM guest. Chrome Remote Desktop connects to the outer host, and Virtual Machine Manager opens the Ubuntu guest console. The hardening described here was applied inside the guest.

| Item | Observed configuration |
| --- | --- |
| Cloud host | `isa-lab-host` |
| Guest name in Virtual Machine Manager | `isa-ubuntu-desktop` |
| Guest hostname | `isa-pc` |
| Guest account used for verification | `isa-pc1` |
| Operating system | Ubuntu 26.04.1 LTS |
| Virtual hardware model | QEMU Standard PC, Q35 + ICH9 |
| Processor shown in guest settings | Intel Xeon × 2 |
| Memory shown in guest settings | 6.0 GiB |
| Disk capacity shown in guest settings | 42.9 GB |

![Fresh Ubuntu guest desktop](evidence/base-desktop.png)

*Figure 1. Ubuntu Desktop running in the KVM guest before the documented hardening work.*

![Guest operating system and virtual hardware](evidence/base-specs.png)

*Figure 2. Guest settings identify Ubuntu 26.04.1 LTS, hostname isa-pc, two virtual processors, 6.0 GiB of memory and 42.9 GB of disk capacity.*

I collected initial settings before changing each category, reviewed the relevant CIS recommendations, applied the changes with administrative privileges, and checked the resulting configuration. I restarted the guest before verifying controls 3–8 so the checks reflected a new desktop session. Before and after terminal output was saved in `~/isa-evidence/03-08-before.txt` and `~/isa-evidence/03-08-after.txt`. Configuration backups were placed in `~/isa-evidence/config-backup/`.

The six supplied screenshots cover the desktop, system specifications and controls 1–2. Controls 3–8 below contain the recorded terminal results; their screenshot placeholders must be filled before final submission. A terminal value confirms the checked setting, but it does not prove every possible attack or user interaction was tested.

## 3 Summary of My Eight Controls

| No. | Category | Main change | CIS recommendations [1] | Evidence status |
| --- | --- | --- | --- | --- |
| 1 | Host-based firewall | Enabled UFW with incoming denial and logging | 4.1.2, 4.1.3, 4.1.5 | Before/after screenshots attached |
| 2 | Unnecessary network services | Removed Avahi and its `ipp-usb` dependency | 2.1.2 | Before/after screenshots attached |
| 3 | Login warning banners | Replaced OS-identifying text with an authorization warning | 1.6.2, 1.6.3, 1.6.7, 1.6.8 | Terminal results recorded; screenshots pending |
| 4 | Screen locking | Enforced a 180-second idle policy and immediate locking | 1.7.3 | Terminal results recorded; screenshots pending |
| 5 | Removable media handling | Disabled automatic mounting/opening and locked the policy | 1.7.4, 1.7.5 | Terminal results recorded; screenshots pending |
| 6 | Scheduled-job access | Created a root-only crontab allowlist | 2.4.1.9 | Terminal results recorded; screenshots pending |
| 7 | Default file permissions | Changed the default umask to `027` | 5.4.3.3 | Terminal results recorded; screenshots pending |
| 8 | Process debugging restrictions | Tightened `ptrace_scope` from `1` to `2` | 1.5.3 | Terminal results recorded; screenshots pending |

## 4 Implemented Controls

### Control 1 Host-Based Firewall

**Before.** `sudo ufw status verbose` reported `Status: inactive`. The socket inventory also showed Avahi listening on UDP port 5353. An inactive guest firewall provides no UFW filtering when network connectivity is available. The socket listing alone does not establish internet reachability.

![Firewall before hardening](evidence/01-firewall-before.png)

*Figure 3. The initial firewall check reports inactive UFW. The same terminal shows the listening-socket inventory.*

**Change.** I enabled UFW, denied incoming connections by default, retained outgoing access, set the routed default to deny and enabled low-level logging. The configuration steps were:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw default deny routed
sudo ufw logging low
sudo ufw enable
```

**After.** The recorded output was:

```text
Firewall is active and enabled on system startup
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
```

Additional checks returned `enabled` for `systemctl is-enabled ufw.service`, `active` for `systemctl is-active ufw.service`, and `DEFAULT_FORWARD_POLICY="DROP"` in `/etc/default/ufw`.

![Firewall after hardening](evidence/01-firewall-after.png)

*Figure 4. UFW is active, logging is enabled and incoming traffic is denied by default.*

**Reason and tradeoff.** Default incoming denial reduces exposure to unsolicited connections. Services intentionally offered by the guest would need explicit allow rules. Outgoing traffic remains allowed for normal desktop use and package downloads; therefore I am not claiming the Level 2 outgoing-denial recommendation, CIS 4.1.4. The benchmark explains that `disabled (routed)` can reflect disabled kernel forwarding; the recorded `DROP` policy provides the separate configuration check [1, §§4.1.2–4.1.5, pp. 547–554]. No external port-scan test was recorded.

### Control 2 Remove Unnecessary Network Services

**Before.** Both `avahi-daemon.service` and `avahi-daemon.socket` were enabled and active. Avahi had UDP listeners on `0.0.0.0:5353` and `[::]:5353`. Its local service-discovery functions were not needed for this lab.

![Avahi before removal](evidence/02-services-before.png)

*Figure 5. Avahi's service and activation socket are running, with IPv4 and IPv6 UDP port 5353 listeners.*

**Change.** I first simulated removal to inspect the dependencies. The simulation identified only `avahi-daemon` and `ipp-usb` for removal. I then removed both packages:

```bash
sudo apt-get --simulate purge avahi-daemon
sudo systemctl stop avahi-daemon.socket avahi-daemon.service
sudo apt-get purge -y avahi-daemon ipp-usb
```

**After.** I checked:

```bash
dpkg-query -s avahi-daemon ipp-usb
sudo ss -ulpn | grep ':5353'
```

Both packages were reported as not installed, and the port check returned no matching listener.

![Avahi removal and verification](evidence/02-services-after.png)

*Figure 6. The package removal completes, the package query confirms both packages are absent, and the final UDP port 5353 check produces no matching output.*

The screenshot also records canceled stop jobs and a temporary socket-activation warning during removal. I used the final package and socket checks to establish the resulting state instead of assuming that the initial stop command succeeded.

**Reason and tradeoff.** Removing an unused discovery service reduces the guest's attack surface. The tradeoff is loss of Avahi-based local discovery and the removed `ipp-usb` printing functionality. This implements a recommendation classified as Level 2 for workstations; it was selected because those features were unnecessary in our lab [1, §2.1.2, pp. 283–284]. Other services, such as the loopback CUPS listener, were not claimed as removed.

### Control 3 Login Warning Banners

**Before.** `/etc/issue` contained `Ubuntu 26.04.1 LTS \n \l`, and `/etc/issue.net` contained `Ubuntu 26.04.1 LTS`. These identified the operating system and did not provide an authorization warning.

**Change.** I replaced both files with the same warning and set their ownership and permissions:

```bash
printf '%s\n' \
  'ISA Project Group lab system. Authorized users only. Activity may be logged.' | \
  sudo tee /etc/issue >/dev/null
sudo cp /etc/issue /etc/issue.net
sudo chown root:root /etc/issue /etc/issue.net
sudo chmod 644 /etc/issue /etc/issue.net
```

**After.** `cat /etc/issue /etc/issue.net` displayed the warning twice:

```text
ISA Project Group lab system. Authorized users only. Activity may be logged.
ISA Project Group lab system. Authorized users only. Activity may be logged.
```

**Reason and tradeoff.** The warning communicates intended access and removes the version-identifying banner text. It does not enforce authentication or prove that activity is actually logged. Editing `/etc/issue.net` alone also does not configure an SSH login banner; that separate behavior was not claimed or tested [1, §§1.6.2–1.6.3, pp. 226–229; §§1.6.7–1.6.8, pp. 237–240].

**Screenshot placeholders:** Add `03-banners-before.png` and `03-banners-after.png`. Include `stat -c '%a %U:%G %n' /etc/issue /etc/issue.net` in the after evidence to confirm the configured ownership and mode.

### Control 4 Enforced Screen Locking

**Before.** The GNOME idle delay was `uint32 300`, the lock delay was `uint32 0`, and locking was enabled. The idle and lock-delay settings were writable by the user. The default locking values were already reasonable; the main gap addressed was the ability to relax them.

**Change.** I configured `/etc/dconf/profile/user` with:

```text
user-db:user
system-db:local
```

I created `/etc/dconf/db/local.d/99-isa-screen-lock` with:

```ini
[org/gnome/desktop/session]
idle-delay=uint32 180

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
```

I placed the following key paths in `/etc/dconf/db/local.d/locks/99-isa-screen-lock`, ran `sudo dconf update`, and restarted the guest:

```text
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
```

**After.** The new session reported:

| GNOME setting | Value | Writable |
| --- | --- | --- |
| `org.gnome.desktop.session idle-delay` | `uint32 180` | `false` |
| `org.gnome.desktop.screensaver lock-delay` | `uint32 0` | `false` |
| `org.gnome.desktop.screensaver lock-enabled` | `true` | `false` |

These were checked using `gsettings get` and `gsettings writable` for the listed schema/key pairs.

**Reason and tradeoff.** A three-minute idle policy with no extra locking delay limits unattended-session access. Locking the keys prevents ordinary users from changing that policy through GNOME settings. The shorter idle period can interrupt reading or demonstrations. Configuration and key lockdown were verified, but a timed idle-lock demonstration was not captured [1, §1.7.3, pp. 261–265].

**Screenshot placeholders:** Add `04-screen-lock-before.png` and `04-screen-lock-after.png`, showing the settings and writable checks.

### Control 5 Removable Media Handling

**Before.** GNOME reported `automount=true`, `automount-open=true` and `autorun-never=true`. Automatic mounting and opening were enabled. Autorun prevention was already enabled, so I retained it rather than claiming it was newly switched on.

**Change.** I created `/etc/dconf/db/local.d/99-isa-media`:

```ini
[org/gnome/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true
```

The following paths were added to `/etc/dconf/db/local.d/locks/99-isa-media`. The system database was rebuilt using `sudo dconf update`, followed by a guest restart.

```text
/org/gnome/desktop/media-handling/automount
/org/gnome/desktop/media-handling/automount-open
/org/gnome/desktop/media-handling/autorun-never
```

**After.** Checks under `org.gnome.desktop.media-handling` returned:

| Key | Value | Writable |
| --- | --- | --- |
| `automount` | `false` | `false` |
| `automount-open` | `false` | `false` |
| `autorun-never` | `true` | `false` |

**Reason and tradeoff.** The desktop no longer automatically mounts or opens inserted media, and users cannot override the selected GNOME policy. Legitimate media may require an explicit mounting action. This is not a blanket USB-device ban, and no physical-media insertion test was recorded. Automatic-mount restrictions are Level 2 workstation recommendations, while autorun prevention is Level 1 [1, §§1.7.4–1.7.5, pp. 266–272].

**Screenshot placeholders:** Add `05-media-before.png` and `05-media-after.png` using the three value checks and three writable checks.

### Control 6 Restrict Scheduled-Job Access

**Before.** `crontab` was installed, but neither `/etc/cron.allow` nor `/etc/cron.deny` existed. There was no explicit account allowlist. The initial checks did not establish whether every ordinary user could use `crontab`; that behavior depends on the installation's configuration [1, §2.4.1.9].

**Change.** I created an explicit allowlist containing only root:

```bash
printf '%s\n' root | sudo tee /etc/cron.allow >/dev/null
sudo chown root:crontab /etc/cron.allow
sudo chmod 640 /etc/cron.allow
```

**After.** The checks returned:

```text
640 root:crontab /etc/cron.allow
cat: /etc/cron.allow: Permission denied
You (isa-pc1) are not allowed to use this program (crontab)
See crontab(1) for more information
```

The mode and ownership match the selected benchmark guidance. The ordinary account's failed direct read is consistent with the restricted permissions, while the failed `crontab -l` demonstrates denied access to the program. The allowlist was written as root-only, but its contents still need a final privileged read using `sudo cat /etc/cron.allow` for screenshot evidence.

**Reason and tradeoff.** The policy restricts administration of personal cron tables to an approved account. Ordinary users lose the ability to create or modify their own cron jobs through `crontab`. This does not disable the cron daemon or establish that pre-existing scheduled jobs were removed [1, §2.4.1.9, pp. 388–391].

**Screenshot placeholders:** Add `06-cron-before.png` and `06-cron-after.png`. Use `stat`, `sudo cat /etc/cron.allow` and an ordinary-user `crontab -l` for the after image.

### Control 7 Restrictive Default File Permissions

**Before.** The shell umask was `0002`. No active `UMASK` line was shown in `/etc/login.defs`, and `USERGROUPS_ENAB` was `yes`. With conventional file-creation modes, this mask permits group writing and access by other users; actual before-created sample files were not captured.

**Change.** I set `UMASK 027` in `/etc/login.defs`, created `/etc/profile.d/99-isa-umask.sh` containing `umask 027`, and added the same mask to `/etc/bash.bashrc` for interactive Bash sessions. In `/etc/pam.d/common-session`, I configured:

```text
session optional pam_umask.so umask=0027 nousergroups
```

The `nousergroups` option prevents private-user-group handling from relaxing the group bits. The existing PAM module entry was edited where present instead of blindly adding a duplicate. I then restarted the guest and tested creation of a directory and file:

```bash
umask
mkdir -p ~/isa-evidence/permission-check
touch ~/isa-evidence/permission-check/sample.txt
stat -c '%a %n' ~/isa-evidence/permission-check \
    ~/isa-evidence/permission-check/sample.txt
```

**After.** The recorded results were:

```text
0027
750 /home/isa-pc1/isa-evidence/permission-check
640 /home/isa-pc1/isa-evidence/permission-check/sample.txt
```

The directory allows its owner full access and its group read/traverse access; the file allows owner read/write and group read. Neither grants access to other users.

**Reason and tradeoff.** A restrictive creation default reduces accidental exposure of newly created files. Group collaboration may require deliberate permission changes. This does not retroactively change existing files and remains a default that a user can change for their own process. Future PAM regeneration may remove the custom arguments, so my partner's password-policy work must preserve and recheck them [1, §5.4.3.3, pp. 756–761].

**Screenshot placeholders:** Add `07-umask-before.png` and `07-umask-after.png`, including the new-session mask and sample file/directory modes.

### Control 8 Restrict Process Debugging

**Before.** `sysctl kernel.yama.ptrace_scope` returned `1`. This was already within the benchmark's permitted values of `1`, `2` or `3`; I selected a stricter setting for this lab rather than describing the original value as noncompliant.

**Change.** I created and loaded a persistent setting:

```bash
printf '%s\n' 'kernel.yama.ptrace_scope = 2' | \
  sudo tee /etc/sysctl.d/99-isa-process.conf >/dev/null
sudo sysctl -p /etc/sysctl.d/99-isa-process.conf
```

**After.** After the guest restart, the check returned:

```text
kernel.yama.ptrace_scope = 2
```

**Reason and tradeoff.** Value `2` restricts ptrace use to processes with `CAP_SYS_PTRACE`, reducing ordinary-user debugging access to processes. It can prevent legitimate debugging tools from working without elevated privileges. The persistent runtime setting was verified, but an attempted debugger attachment was not tested [1, §1.5.3, pp. 188–192].

**Screenshot placeholders:** Add `08-ptrace-before.png` and `08-ptrace-after.png`, showing the sysctl value before and after reboot.

## 5 Partner Contribution

The categories below are assigned for the remaining work. They are **pending** and are not included in the count of completed controls. Replace each placeholder with actual findings and results; do not copy expected results as if they were observed.

### Control 9 Updates and Package Delivery

**Contributor:** [partner name]  
**CIS reference:** 1.2.1.11 and 1.2.2.1  
**Before:** [repository URLs, update policy and pending packages]  
**Changes and commands:** [files/settings changed and packages updated]  
**After:** [observed update checks, timers and dry-run results]  
**Reason and tradeoff:** [security purpose, network/disk use, any held updates]  
**Evidence:** [add captioned before/after screenshots]  
**Status:** Pending

### Control 10 AppArmor Application Confinement

**Contributor:** [partner name]  
**CIS reference:** 1.3.1.2 and 1.3.1.4; custom scoped profile as a lab extension  
**Before:** [existing profiles/state and harmless unconfined test]  
**Changes and commands:** [restriction and enforced profile]  
**After:** [actual allowed/denied reads and denial event]  
**Reason and tradeoff:** [policy scope and legitimate paths restricted]  
**Evidence:** [add captioned before/after screenshots]  
**Status:** Pending

### Control 11 Bootloader Protection

**Contributor:** [partner name]  
**CIS reference:** 1.4.1  
**Before:** [initial GRUB protection state]  
**Changes and commands:** [configuration without passwords or hashes]  
**After:** [normal boot and protected editing tests]  
**Reason and tradeoff:** [boot editing protection and recovery restrictions]  
**Evidence:** [add captioned before/after screenshots]  
**Status:** Pending

### Control 12 Network Kernel Settings

**Contributor:** [partner name]  
**CIS reference:** [exact selected 3.3 recommendation IDs]  
**Before:** [original runtime values]  
**Changes and commands:** [persistent sysctl file and values]  
**After:** [runtime checks after reboot and DNS check]  
**Reason and tradeoff:** [endpoint policy and routing restrictions]  
**Evidence:** [add captioned before/after screenshots]  
**Status:** Pending

### Control 13 Password Quality Policy

**Contributor:** [partner name]  
**CIS reference:** 5.3.2.3 and selected 5.3.3.2 recommendations  
**Before:** [original PAM/quality configuration]  
**Changes and commands:** [quality policy and preservation of the existing umask]  
**After:** [actual weak-password rejection and strong-password acceptance]  
**Reason and tradeoff:** [password strength, usability and scope limits]  
**Evidence:** [add captioned before/after screenshots without passwords]  
**Status:** Pending

### Control 14 Privilege Escalation Policy

**Contributor:** [partner name]  
**CIS reference:** 5.2.2 and 5.2.6  
**Before:** [sudo version and active policy]  
**Changes and commands:** [validated sudo policy]  
**After:** [prompting and noninteractive authentication test]  
**Reason and tradeoff:** [reduced credential reuse and repeated prompts]  
**Evidence:** [add captioned before/after screenshots]  
**Status:** Pending

### Control 15 Persistent Logging and Account Auditing

**Contributor:** [partner name]  
**CIS reference:** 6.1.1.1.6, 6.2.1.1–2 and selected 6.2.3.12–14  
**Before:** [journal storage and auditing state]  
**Changes and commands:** [journal policy and account-file audit rules]  
**After:** [actual audit event and a journal message retained across reboot]  
**Reason and tradeoff:** [traceability, disk usage and retention limits]  
**Evidence:** [add captioned before/after screenshots]  
**Status:** Pending

## 6 Current Results and Conclusion

My eight categories changed the guest's security configuration in several ways: UFW now filters incoming traffic, an unnecessary discovery service has been removed, GNOME policies are locked against ordinary-user changes, personal cron administration is restricted, and new files receive tighter permissions. The post-restart checks also confirmed the stricter umask and process-debugging setting.

Some defaults were already secure. Screen locking and autorun prevention were already enabled, and `ptrace_scope=1` already satisfied the benchmark's acceptable-value check. In those cases, the work enforced or tightened the policy rather than correcting a falsely reported failure.

Eight categories have been implemented and checked at the scope described above. The project is not yet complete: seven partner categories remain, screenshots for controls 3–8 need to be attached, and the combined configuration needs final verification after the partner's changes. These remaining items must be completed before stating that the group has met the minimum of 15 documented categories.

<!-- Replace this draft conclusion with a combined conclusion after controls 9–15 and final checks are complete. -->

## 7 Evidence Still Needed Before Submission

- [ ] Fill in both members' full names and the section.
- [ ] Attach before/after screenshots for controls 3–8. Use the saved original before output; clearly label any later screenshot of saved logs. Do not present a recreated configuration as original before evidence.
- [ ] Capture a privileged read of `/etc/cron.allow` and the banner ownership/mode checks.
- [ ] Add the partner's actual sections and captioned screenshots for controls 9–15.
- [ ] Verify that earlier controls remain in place after the password-policy work and final reboot.
- [ ] Update the results, control count and conclusion from the completed evidence.
- [ ] Remove draft placeholders and this checklist from the submission copy once resolved.

## 8 References

[1] Center for Internet Security. (2026, August 26). *CIS Ubuntu Linux 26.04 LTS Benchmark* (Version 1.0.0). Supplied course reference PDF. Recommendation numbers and page citations in this report use the document's printed page numbers.

[2] *Information Security and Assurance 1 Final Project*. Supplied project instructions. Requirements used here: Ubuntu Desktop VM, initial-state examination, at least 15 distinct control categories, CIS-based justification, and annotated before/after evidence.

<!-- Keep the evidence folder beside this Markdown file so its screenshot links render locally. The ZIP version preserves that arrangement. -->
