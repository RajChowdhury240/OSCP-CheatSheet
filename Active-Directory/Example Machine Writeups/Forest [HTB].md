# HackTheBox-Forest

## NMAP
```bash

PORT     STATE SERVICE           REASON          VERSION                                                                                            
53/tcp   open  domain?           syn-ack ttl 127
| fingerprint-strings:                     
|   DNSVersionBindReqTCP:                                              
|     version                                           
|_    bind                                                        
88/tcp   open  spark             syn-ack ttl 127 Apache Spark             
135/tcp  open  msrpc?            syn-ack ttl 127                          
139/tcp  open  netbios-ssn?      syn-ack ttl 127
464/tcp  open  kpasswd5?         syn-ack ttl 127                     
593/tcp  open  ncacn_http        syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?          syn-ack ttl 127
3268/tcp open  ldap              syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)         
3269/tcp open  globalcatLDAPssl? syn-ack ttl 127\                     
5985/tcp open  http              syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods:                                                           
|_  Supported Methods: HEAD                   
9389/tcp open  adws?             syn-ack ttl 127
Host script results:                                                      
|_clock-skew: mean: 3h40m48s, deviation: 4h57m02s, median: 10m45s
| smb-os-discovery:                                                       
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST            
|   NetBIOS computer name: FOREST\x00 
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2021-05-11T11:43:01-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
|_smb2-time: Protocol negotiation failed (SMB2)


```

Here we port 88 open which is for Kerberos and port 3268 for ldap which tells that this is an Active Directory machine , we also have smb port open on the machine so we can check if there are any smb shares or not 

## PORT 139/445 (SMB)
<img src="https://imgur.com/MXXEZEo.png"/>

We get an authentication error means that Anonymous login is disabled so let's move to ldap

## PORT 3268 (LDAP)
LDAP stands for `Lightweight Directory Access Protocol` , it is used for querying /locating data  about organizations, individuals and other resources such as files and devices in a network  so there is a tool for performing searches for users ,groups and etc.

https://github.com/ropnop/go-windapsearch

This is the tool that I found was working , there is no need to clone this simply go to releases and download the compiled binary

`windapsearch-linux-amd64 -d 'htb.local' --dc 10.10.10.161 -m users`


<img src="https://imgur.com/coBW6Aw.png"/>

Let's break down the syntax of this tool 

-d ---> This specifies the domain name which `htb.local`

--dc ---> This specifies domain controller ip (machine ip)

-m ---> This is for specifying module to use in this case we are using `users` module which will try to query information about users

<img src="https://imgur.com/aF6GDOX.png"/>

These are the available modules . We know that service accounts are usually kerberoastable so we are going to search for a service account , in order to that we need to run a custom module in which we are going to use a filter `(objectclass=*)` when executing this query, we will be presented with all objects and all attributes available in the tree 

<img src="https://imgur.com/ub9rVmG.png"/>

This will show a lot of output so start searching for `Service Accounts` till you find a service account name

<img src="https://i.imgur.com/zUNFGBD.png"/>

Alternatively we can use `enum4linux` which can enumerate smb shares and query LDAP and look for users and shares. 

<img src="https://i.imgur.com/xllYBNX.png"/>

<img src="https://i.imgur.com/YWNKeE9.png"/>

We can see this service account `svc-alfresco` as the prefix `svc` is for service, so we will use impacket GetNPUsers.py since this service account won't require kerberos pre-authentication this is know nas `AS-REP Roasting` you'll see the hash will be different than normal kerberos hash 

<img src="https://imgur.com/OCYBPly.png"/>

So we can crack this hash either with john or hashcat,  I will be using `hashcat` and we may need to know the type of hash in hashcat so going to hashcat examples we can find which mode we need to supply

<img src="https://i.imgur.com/kKvAxhT.png"/>

<img src="https://imgur.com/Bcfwz1u.png"/>

<img src="https://i.imgur.com/iIsQeR7.png"/>

Perfect we have the password , now  we can use `bloodhound-injestor` to collection information about the AD environment

https://github.com/fox-it/BloodHound.py

```
python3 bloodhound.py -d 'htb.local' -u 'svc-alfresco' -p 's3rvice' -gc 'FOREST.htb.local' -c all -ns 10.10.10.161
```

<img src="https://imgur.com/m0puEJJ.png"/>

We'll have these json files so we put all these files in an archive and launch bloodhound and import that archive file

<img src="https://i.imgur.com/71QYhAr.png"/>

<img src="https://imgur.com/jMgkkz0.png"/>

We can ran query `Find All Domain Admins` and can see the result

<img src="https://imgur.com/dtBHB4q.png"/>

Run the query `Find AS-REP Kerbroastable Users`

<img src="https://i.imgur.com/lUvxP24.png"/>

And mark the account as owned , click on the account and on the left side you can see in how may groups this account has permissions

<img src="https://i.imgur.com/XR9pTSC.png"/>

Select `Reachable Higher Targets`

<img src="https://i.imgur.com/O21nLQ7.png"/>

Exaplain about WriteDACL

Login with the credentials with `evil-winrm` and upload `PowerView.ps1` powershell script

https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1


<img src="https://i.imgur.com/i5ODJA2.png"/>


Now we need to create a new user , so I am going to create a user named `arz`, then add it to the `Exchange Windows Permissions` group which is a domain group. After that we will create variable having arz's password which should converted it to a secure form and create a powershell object through that ,lastly we will use powerview's `Add-DomainObjectAcl` function that will allow us to give this user `DCSync rights` which are replication rights which will allows us to rrequest password hashes from the Domain Controller.

<img src="https://i.imgur.com/r8FuTST.png"/>

<img src="https://i.imgur.com/A2tEZDs.png"/>


Now we need to run impacket's `secretsdump.py` which will dump password hashes from `NTDS.dit` file

<img src="https://i.imgur.com/vy8ifHL.png"/>

We could have also done this we service account as well

<img src="https://i.imgur.com/qTHIh8S.png"/>

<img src="https://i.imgur.com/qTHIh8S.png"/>

<img src="https://i.imgur.com/yTiOLOx.png"/>
