# HackTheBox-Active

## Rustscan

```bash

PORT      STATE SERVICE       REASON          VERSION
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2021-05-14 04:03:39Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
49152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC

```


## PORT 139/445 (SMB)

We can try to anonnmyously login to see how many smb shares are there

<img src="https://imgur.com/AzI0T6A.png"/>

So let's try one by one which share we can access

<img src="https://imgur.com/FHwamyw.png"/>

We have access to `Replication` share 

Using `smbget` download everything

<img src="https://imgur.com/iHIZsdy.png"/>

I spend time going over to directories here and there and found a XML file called `Groups.xml`

<img src="https://imgur.com/or4fKMm.png"/>

Here we can see service account `SVC_TGS` and a encrypted password so I searched for Groups.xml file and straight away the results came for decrypting password , referring to this article 

https://myexploit.wordpress.com/groups-xml/

So this file is called Group policy preference file which has the stored encrypted password for a user at the of user creation and it's encrypted with AES256 but it's public is available in the documentation so there are many tools and scripts that can decrypt this password  ,I used the command `gpp-decrypt <ecnrypted_password>` which is a built in tool found in kali linux 
 
<img src="https://i.imgur.com/d90KFYK.png"/>

<img src="https://imgur.com/BetwVTz.png"/>

We can see it's a valid password but it didn't showed the status "Pwned!" so I think we can't get a shell with this so we can use `Python bloodhound injestor` to gather information about AD environment 

https://github.com/fox-it/BloodHound.py

```
python3 bloodhound.py -d 'active.htb' -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -gc 'active.htb' -c all -ns 10.10.10.100
```

<img src="https://i.imgur.com/bj1mvUe.png"/>

Put all these json files in an archive and import it to Bloodhound GUI, drag and drop the archive file into GUI

<img src="https://imgur.com/0d7OfEL.png"/>

<img src="https://imgur.com/2Tv7V2w.png"/>

Running the query `Find all Domain Admins` we can see the results which means those json files are imported 

<img src="https://imgur.com/ec53Gfa.png"/>

On running  the query `List All Kerberoastable Users` we can see there's an Administrator account so using the credentials we found we can get the TGT(Ticket Granting Ticket) hash 


<img src="https://i.imgur.com/EGA6cqi.png"/>

To crack this hash I will be using `hashcat ` , since we need to specify the mode of hash I am going to search for krb5tgs hash mode

https://hashcat.net/wiki/doku.php?id=example_hashes

<img src="https://imgur.com/5rASqEV.png"/>

<img src="https://imgur.com/bbFp8Wv.png"/>

And we will just for the hash to be cracked

<img src="https://i.imgur.com/MUV1rFl.png"/>

Now again let's check this password with crackmapexec

<img src="https://i.imgur.com/SO3LrFL.png"/>

We get a "Pwned" status it means we can get a shell now , but before that let's see if we can dump hashses as `Administrator` has DCsync rights meaning to replicate AD information so we can dump hashes from file called NTDS.dit which holds hashes of all users in AD

<img src="https://imgur.com/zSBtZiw.png"/>

And it looks like we can ,so let's just get a shell with `psexec.py` as SYSTEM 

<img src="https://imgur.com/Ibiprkb.png"/>
