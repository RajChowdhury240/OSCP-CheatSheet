# HackTheBox - Resolute

## NMAP

```bash
PORT      STATE SERVICE      VERSION        
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2021-12-15 09:37:43Z)                      
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)               
464/tcp   open  kpasswd5?         
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0     
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)    
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found                    
9389/tcp  open  mc-nmf       .NET Message Framing        
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0             
|_http-title: Not Found                      
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49688/tcp open  msrpc        Microsoft Windows RPC
49862/tcp open  unknown
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

```

From port 88 this tells us that this is an active directory because on this port `kerberos` runs which is responsible for authenticating users so knowing this will help us in our enumeration and what steps we should take

## SMB/LDAP

Since smb is enabled we can try to login as anonymous user if it's disabled

<img src="https://i.imgur.com/lrb6YVR.png"/>

now we can try to enumerate LDAP as from there we can get some information of what are user names , group names and domain name of the machine using either `enum4linux-ng` or `windapsearch`

<img src="https://i.imgur.com/p3pALUm.png"/>

<img src="https://i.imgur.com/Dc0LQVd.png"/>

We have the usernames just need to grep for `username` and then use these names against `kerbrute` to find which are valid domain users and we one of these users have pre-authentication disabled then we can get a user hash which we can crack

<img src="https://i.imgur.com/WdBCxC1.png"/>

We can sort this only to grab username by using `awk`

<img src="https://i.imgur.com/xsniwoV.png"/>

So running kerbrute we found 24 usernames that are valid out of 27

<img src="https://i.imgur.com/63jbK6C.png"/>

## Foothold

If we go back to enum4linux result we see in the description a password for `marko` user

<img src="https://i.imgur.com/qlh0Quy.png"/>

But this password didn't worked for him

<img src="https://i.imgur.com/sXPDe2U.png"/>

So next option is to just perform a passwordspray attack

<img src="https://i.imgur.com/2Pi1mOQ.png"/>

We can list shares on smb

<img src="https://i.imgur.com/YcoAURW.png"/>

The `NETLOGON` share seems to have nothing in it

<img src="https://i.imgur.com/Yba1SaF.png"/>

So I tried to see if I can kerberoast a user which is assoiciated with any SPNs but doesn't seem if there were any accounts like that 

<img src="https://i.imgur.com/PKI7Usa.png"/>

Then I realized that I didn't check `winrm`

<img src="https://i.imgur.com/8NSjD3D.png"/>

And we can actually use it to get a remote session using `evil-winrm`

So to enumrate AD , we have two options either running `sharphound`  powershell script or `python bloodhound injestor`

<img src="https://i.imgur.com/2pvClra.png"/>

Import the json files that this script generates and after that search the username so that we can mark it as `pwned` and see if we can find a path to higher targets by running the pre-built query

<imgs src="https://i.imgur.com/VTebdQn.png"/>

Running the query we don't see anything interesting that we can do with this user

<img src="https://i.imgur.com/bvJ2g8t.png"/>


But if we look at `ryan` user , he's in the group `Contractors`

<img src="https://i.imgur.com/oYcnW78.png"/>

And if we further explore this group , that is a member of `DNSAdminsGroup`

<img src="https://i.imgur.com/OEtflR8.png"/>

## Privilege Escalation (ryan)

Getting on the machine through `evil-winrm` we can see a hidden directory called `PSTranscripts` through `dir -Force`
 
<img src="https://i.imgur.com/1wPL6En.png"/>

<img src="https://i.imgur.com/ZMPo5XC.png"/>

We can find a text file by going into this directory

<img src="https://i.imgur.com/YgnBDJM.png"/>

Reading this file we will be able to get the password for ryan

<img src="https://i.imgur.com/RYv9KHy.png"/>

<img src="https://i.imgur.com/02hnInm.png"/>

<img src="https://i.imgur.com/s9SMP2b.png"/>

## Privilege Escalation (Administrator)

We know that ryan is a member of contractors group and that group is a member of DNSAdmins group so that makes ryan a member of that group

<img src="https://i.imgur.com/WLP5Wk5.png"/>

This can lead to privilege escalation to SYSTEM user as having the permission to control dns service we can load a malicious dll file by generating it through `msfvenom` and hosting it through smb share and then loading it with `dnscmd` then stopping the dns service with `sc.exe stop dns` and restarting it with `sc.exe start dns` to start dnsservice with our malicious dll file 

Generating the dll file 

<img src="https://i.imgur.com/tABGHF8.png"/>

Using impacket's smbserver to start smbserver

<img src="https://i.imgur.com/SXn4wup.png"/>

Now there was an issue with this box , don't know if it's the same with other users, when I was following this article for abusing DNSAdmins group it wouldn't give me the reverse shell neither it would execute commands from the payload `msfvenom -p windows/x64/exec cmd='net group "Administrator" melanie /add' -f dll > dns.dll`

Also when we download the dll on the machine it would be removed under a minute so we needed to be quick , so the way I got SYSTEM was , I stopped the dns service first then loaded the dll then started the dns service and saw the response on smbserver and got a shell on netcat

<img src="https://i.imgur.com/vYsSEy8.png"/>

<img src="https://i.imgur.com/PmNKGfy.png"/>

<img src="https://i.imgur.com/dJ45hFI.png"/>

To get a proper shell  we can now just add ryan to `Domain Admins` group or local group `Administrators` 

<img src="https://i.imgur.com/hOnzAO4.png"/>

We can verify it with `net user ryan`

<img src="https://i.imgur.com/dJkDSBB.png"/>

Again , we need to be quick to dump hashes and perform pass the hash attack because it will revert back the changes

<img src="https://i.imgur.com/q5n6Nzf.png"/>

<img src="https://i.imgur.com/V5IHOZS.png"/>


## References
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise
