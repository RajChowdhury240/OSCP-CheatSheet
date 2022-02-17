# TryHackMe-THROWBACK-PROD(10.200.34.219)

## NMAP

```
Nmap scan report for 10.200.34.219                                        
Host is up (0.19s latency).                                               
Not shown: 993 filtered ports                                             
PORT     STATE SERVICE       VERSION                                      
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0) 
| ssh-hostkey:                                                            
|   2048 85:b8:1f:80:46:3d:91:0f:8c:f2:f2:3f:5c:87:67:72 (RSA)
|   256 5c:0d:46:e9:42:d4:4d:a0:36:d6:19:e5:f3:ce:49:06 (ECDSA)
|_  256 e2:2a:cb:39:85:0f:73:06:a9:23:9d:bf:be:f7:50:0c (ED25519)
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:                                                           
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Throwback Hacks                                             
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: THROWBACK                                                
|   NetBIOS_Domain_Name: THROWBACK                                        
|   NetBIOS_Computer_Name: THROWBACK-PROD
|   DNS_Domain_Name: THROWBACK.local
|   DNS_Computer_Name: THROWBACK-PROD.THROWBACK.local
|   DNS_Tree_Name: THROWBACK.local
|   Product_Version: 10.0.17763
|_  System_Time: 2021-02-22T17:08:55+00:00
| ssl-cert: Subject: commonName=THROWBACK-PROD.THROWBACK.local
| Not valid before: 2021-02-21T16:52:43
|_Not valid after:  2021-08-23T16:52:43
|_ssl-date: 2021-02-22T17:09:35+00:00; +13s from scanner time.
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
|_clock-skew: mean: 12s, deviation: 0s, median: 12s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-22T17:08:58
|_  start_date: N/A

```

### PORT 80 (HTTP)

<img src="https://imgur.com/JBjLauV.png"/>

Since this host has AD running so we can run a tool called `responder` to start an attack called LLMNR/NBT-NS poisoning

<img src="https://imgur.com/OpMmDhq.png"/>

<img src="https://imgur.com/kweooie.png"/>

I ran this tool for 2 days and it didn't gave me the hash , there was a problem in Throwbacks network so I had to continue looking up the writeups

### Remmina

Since this windows machine has port 3389 open which is for `Remote Desktop Protocol` we can login with PetersJ's passoword which is `Throwback317`

<img src="https://imgur.com/KeBEkmk.png"/>


 
### Installing Starkiller

Starkiller is C2 (Command and Control) frontend interface for "Empire" used for post exploitation without interfereing with the actual machine it self. It is used for enumeration and for  identifiying privilege escalation vectors so for that we need to have `starkiller` and `empire`  


<img src="https://imgur.com/22d5PmO.png"/>

<img src="https://imgur.com/RJoPGls.png"/>

Now we have to `chmod +x starkiller-1.3.2.AppImage` and `./starkiller-1.3.2.AppImage --no-sandbox`

<img src="https://imgur.com/iBx880x.png"/>

We will be presented with a login prompt

<img src="https://imgur.com/b6nbxVz.png"/>

### Installing Empire

Empire is great tool similar to meatsploit for post exploitation and information gathering used on windows machines

Run `git clone https://github.com/BC-SECURITY/Empire.git`

<img src="https://imgur.com/AeIlyAT.png"/>

Run `install.sh`

<img src="https://imgur.com/S5YIcIj.png"/>

This installation would take a long time. So going back to starkiller we log in with the credentials `empireadmin:passowrd123` and we need to make this application listen on defualt port which is  `1337` leet but in order login we want empire to be running

<img src="https://imgur.com/yQgRlJ8.png"/>

<img src="https://imgur.com/LH0xXgZ.png"/>

So our installation for empire is complete but still we need  to install some dependencies

`pip3 install poetry` and  `poetry install` then `poetry run python empire`

<img src="https://imgur.com/T0CKmLl.png"/>

One last thing to do `pip3 install click` and when you run `powershell-empire`

<img src="https://imgur.com/oI7bFsl.png"/> 

And it works but we need to use it with `--rest`,so

<img src="https://imgur.com/uznPAGc.png"/>

By using this option it will use the default ports and will allow us to use frontend which starkiller

<img src="https://imgur.com/jSKqMUA.png"/>

<img src="https://imgur.com/s08duZJ.png"/>

On logging in with the default credentials above

<img src="https://imgur.com/XcK3Ffr.png"/>

Now we are going to create our listener

<img src="https://imgur.com/C9c6HbQ.png"/>

We have our listener created

<img src="https://imgur.com/nLlDDRu.png"/>

Now we need to create our stager which is the payload we are going to transfer on the target machine

<img src="https://imgur.com/jQ2n0qf.png"/>

<img src="https://imgur.com/CWUgbh5.png"/>

<img src="https://imgur.com/SbqbSpy.png"/>

<img src="https://imgur.com/dpeTD8a.png"/>

Click on the download or save icon to save the payload somewhere on your local machine and then start a python3  http server  to host it in order to download it from the target machine

<img src="https://imgur.com/Ydsqj2a.png"/>

The web server is running

<img src="https://imgur.com/kQToAFI.png"/>

We have that on the target machine all we need to do is launch the payload

On launching we will see some information regarding the target machine in the `agents` section

<img src="https://imgur.com/4XJE4QP.png"/>

We can see that starkiller is acting like C2 server which sends commands on the target machine and we can see the output over the GUI

<img src="https://imgur.com/i0l8yno.png"/>

Run `seatbelt` module

<img src="https://imgur.com/QBkCLbY.png"/>

<img src="https://imgur.com/jDwhgPE.png"/>

This module did enumeration for us a found a user with a saved credential

<img src="https://imgur.com/7xIrk2n.png"/>

<img src="https://imgur.com/L9ln4k5.png"/>

Now we have logged in as `admin-petersj` in order to dig deep we have to run mimikatz but for that we need to create another listener and stager in order to run c2 commands as elevated user

<img src="https://imgur.com/bLpUqC1.png"/>

<img src="https://imgur.com/zA88wGT.png"/>

<img src="https://imgur.com/cng57Ba.png"/>

On running this payload again

<img src="https://imgur.com/xvHivNX.png"/>

Now we need to run `mimikatz` module through our C2

<img src="https://imgur.com/lr1IlWS.png"/>

Running `privilege::debug` will give us a status `OK` means we can escalate our privileges to NT-AUTHORITY

<img src="https://imgur.com/QCrgIh9.png"/>

<img src="https://imgur.com/YyeUrWC.png"/>

We ran the command and notice if scroll down a little be we can see the password hashes of the users

<img src="https://imgur.com/KN0s9k0.png"/>

There's a feature in Starkiller which can save all the credentials or hashes found in a neat way

<img src="https://imgur.com/HLRA0Gq.png"/>

Now we have the credentials but don't know on which host these credentials are valid so we are going to something called` Pass The Hash` a realy attack for that we need to run `proxychains` or `autoroute` for that we need  to have meterepreter session 

<img src="https://imgur.com/s3zJGOS.png"/>

<img src="https://imgur.com/ZhlxTI1.png"/>

<img src="https://imgur.com/qnU0AuG.png"/>

<img src="https://imgur.com/gta3t5x.png"/>

<img src="https://imgur.com/2ZpOIBh.png"/>

Install `Crackmapexec`

https://github.com/byt3bl33d3r/CrackMapExec/wiki/Installation#binaries

<img src="https://imgur.com/NWSK4mb.png"/>

We can see that we can ping the ohter machines as well so the task says that the hash from task 10 will work which was from `HumprehyW` 's  hash and the other from the list of credentials we dumped using mimikatz

<img src="https://imgur.com/cf5YlMY.png"/>

<img src="https://imgur.com/Iu9v0Vc.png"/>


PetersJ:Throwback317

runas /savecred /user:<user> /profile "cmd.exe"
	
use auxiliary/server/socks4a