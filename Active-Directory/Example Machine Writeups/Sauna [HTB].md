# HackTheBox - Sauna

## NMAP

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?                                      
| fingerprint-strings:                                   
|   DNSVersionBindReqTCP:   
|     version                                                          
|_    bind
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:       
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0  
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-12-13 14:37:44Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?                                              
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped                                             
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped                                             
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                                                   
|_http-title: Not Found                                                
9389/tcp  open  mc-nmf        .NET Message Framing                 
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC


```

From the port 88 we can say that this is an Active directory machine because on this port kerberos runs for authenticating users also we can see LDAP service running as well

## PORT 139/445 (SMB)

We can try to list shares as an un-authenticated user using `smbmap`

<img src="https://i.imgur.com/WSi7Dnb.png"/>

But this smb is configured to only allow access to authenticated users so let's move on 


## PORT 389 (LDAP)

Through LDAP and SMB I tried to use enumerate usernames by running `enum4linux-ng`

<img src="https://i.imgur.com/Dk8kGA2.png"/>

But it failed to enumerate usernames and groups

<img src="https://i.imgur.com/A56URCw.png"/>

## PORT 80 (HTTP)

<img src="https://i.imgur.com/ZzDtBV2.png"/>

Going into about section , we can see few usernames that we can make a list of then try to see if either one of them has pre-authentication disabled

<img src="https://i.imgur.com/DDhTOIC.png"/>

Other than that I ran `gobuster` , fuzzing for files and directories but didn't found anything interesting

<img src="https://i.imgur.com/5MxUhxQ.png"/>

So the list of usernames I made were

```
FSmith
fsmith
Fsmith
SCoins
scoins
Scoins
HBear
hbear
Hbear
BTaylor
btaylor
Btaylor
SDriver
Sdriver
sdriver
SKerb
Skerb
skerb
Administrator
krbtgt
administrator
```

## Foothold

We can either use impacket's `GetNPUsers.py` or use `kerbrute` to see which users have pre-authentication disabled also to verify which users are valid

<img src="https://i.imgur.com/HuCxUEU.png"/>

And in an instant it dumped the user's hash , also we can get the same output with impacket script as well

<img src="https://i.imgur.com/5fgdIY9.png"/>

Now we can crack this hash using `hashcat` , we can visit hashcat examples page to find out the correct mode of this hash

<img src="https://i.imgur.com/q0mSzIJ.png"/>

<img src="https://i.imgur.com/9IEyoDn.png"/>

<img src="https://i.imgur.com/NJgNqeB.png"/>

port 5985 is open on which winrm runs (windows remote management) through which we can remotely login to a system , so using the credentials we have let's try doing it with `evil-winrm`

<img src="https://i.imgur.com/xhJ44RT.png"/>

We can do some basic enumeration to see in which groups this user is

<img src="https://i.imgur.com/2OTIKCJ.png"/>

So can't really do anything being in those groups , in order to enumerate the AD we can use sharphound that would collect the information and create an archive 

<img src="https://i.imgur.com/2ZCmBMg.png"/>

<img src="https://i.imgur.com/Gty129C.png"/>

We have this archive file generated which has the information of AD objects , we need to download this on our local machine and import this to bloodhound GUI

<img src="https://i.imgur.com/gGQTmnN.png"/>

<img src="https://i.imgur.com/d77NCel.png"/>

<img src="https://i.imgur.com/8zZd6s1.png"/>

Running the pre-built query for finding kerberosatable accounts we see `HSmith`'s account , I tried to use `GetUserSPNs.py` but was failing in retrieving hash even after synchronizing the timezone with the machine

<img src="https://i.imgur.com/1jtaX65.png"/>

Then I tried running `winpeas.exe` but it didn't work

<img src="https://i.imgur.com/B7Vyz0z.png"/>

## Privilege Escalation (svc_loanmgr)

We could try to run `winpeas.bat`

<img src="https://i.imgur.com/Hg8jpsK.png"/>

<img src="https://i.imgur.com/VD0zuEL.png"/>

This gives us clear text password  , but the username here is `svc_loanmgr` so with evil-winrm we can login

<img src="https://i.imgur.com/EBRY1SP.png"/>

## Privilege Escalation (Administrator)

Going back to bloodhound , we can mark this service account as "owned" and seeing if this user can reach to higher targets

<img src="https://i.imgur.com/t6naV7J.png"/>

Here this service account has `GetChangesAll` rights on the domain which means this account can request for DCSync which means that we can ask domain controller for password hashes, either we can use mimkatz or impacket so I will be showing both methods

with `secretsdump.py`

<img src="https://i.imgur.com/GF6IEkM.png"/>


<img src="https://i.imgur.com/Vrshv4l.png"/>

with `mimikatz.exe` (although I tried to use mimikatz.ps1 but it wasn't working)

<img src="https://i.imgur.com/3k7tkN2.png"/>
