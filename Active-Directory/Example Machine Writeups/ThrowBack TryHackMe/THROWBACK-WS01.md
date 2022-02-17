# TryHackMe-THROWBACK-WS01 (10.200.34.222)

## NMAP

```
No ports open on this machine
```

We can get `user.txt` flag from here

<img src="https://imgur.com/xsRg9Ay.png"/>

And for `root.txt`

<img src="https://imgur.com/cUSPJ4C.png"/>

Since we have ran `autoroute` on `THROWBACK-WS01` we can access machines on the network as we were not able to run nmap scan on this machine

<img src="https://imgur.com/OGgwf4O.png"/>

<img src="https://imgur.com/yFaKuRh.png"/>

We can ssh into the machine with BlaireJ's plain text password

<img src="https://imgur.com/PJ4HyKK.png"/>

Now that we have gained inital foothold on WS-01 again we need to do some enumeration with `Bloodhound`.

After installing it on kali machine we can the GUI interface on browser

<img src="https://imgur.com/Ybb3IsB.png"/>

<img src="https://imgur.com/RgkCUOG.png"/>

Now we need to download a file called `Sharphound.ps1` a powershell script to be transfered on WS-01 machine

https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1

To run the script we need to disable antivirus or windows defender on the target machine

https://www.itechtics.com/enable-disable-windows-defender/

`Set-MpPreference -DisableRealtimeMonitoring $true`

<img src="https://imgur.com/AlJDpuw.png"/>

Then run this command to get a map of the AD environment

`Invoke-Bloodhound -CollectionMethod All -Domain THROWBACK.local -ZipFileName loot.zip`

<img src="https://imgur.com/NfjVTcj.png"/>

<img src="https://imgur.com/cGKVQsb.png"/>

Now we need to get this `20210227114234_loot.zip` on our machine

I messed up with the credentials and didn't found a way to reset so I disabled the authentication

`subl /etc/neo4j/neo4j.conf`

<img src="https://imgur.com/PuD7Ala.png"/>

<img src="https://imgur.com/35t7laC.png"/>

Copy that zip file from the target to our local machine

<img src="https://imgur.com/HZvlGCp.png"/>

Simply drag and drop to bloodhound GUI and run quries example get all admins

<img src="https://imgur.com/C9Sr8Mc.png"/>

Run the query `Map Domain Trusts`

<img src="https://imgur.com/aHAiDSP.png"/>


Run the query `List all Kerberoastable Accounts`

<img src="https://imgur.com/awmL00s.png"/>


Run the query `Find Shortest Paths to Domain Admins`

<img src="https://imgur.com/Y5sHUPg.png"/>

Now in order to get kerbroast ticket we need the impacket version 0.9.19

https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19

Reason is if we run with latest version

<img src="https://imgur.com/RCdKOTU.png"/>

We won't get the kerbroast ticket of SQLSERVICE account so on running with older version

<img src="https://imgur.com/gJvzinj.png"/>

On getting that kerbroast hash we need to crack it using `hashcat`

<img src="https://imgur.com/XbWpDwj.png"/>

<img src="https://imgur.com/rmE7npi.png"/>
