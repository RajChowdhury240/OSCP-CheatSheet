# TryHackMe-THROWBACK-DC01(10.200.34.117)



I used SSH to log on the domain controller

<img src="https://imgur.com/eEnWAsQ.png"/>

We can see that we are a normal domain user on this machine so we need to escalate our privileges and the only way to enumerate AD is to use bloodhound so by using the same loot we got from WS-01 we are going to utilize it

Using the query `Find Principals with DCSync Rights`

<img src="https://imgur.com/Q2RPxq3.png"/>

Going into to the documents of jeffersd we find a notice

<img src="https://imgur.com/LYbWm2r.png"/>

Here there's a backup account password and we already found that `backup` has DCsync rights

```
DCSync is a late-stage kill chain attack that allows an attacker to simulate the behavior of Domain Controller(DC) in order to retrieve password data via domain replication
```

By running secretsdump.py we dumped hashes from NTDS.dit

<img src="https://imgur.com/sbSK2qG.png"/>

Now we have a bunch of user hashes but the problem how we can we know which user to target as we need to escalate our privileges so running a command `net localgroup` to see available groups on AD

<img src="https://imgur.com/EUBLwuO.png"/>

We can see there's a group `Administrators`

<img src="https://imgur.com/G7NbGYD.png"/>

So we need to crack `MercerH` 's  hash

<img src="https://imgur.com/LKSymjy.png"/>

To crack the hash we will be using a rules in `hashcat`

<img src="https://imgur.com/dtuvAZL.png"/>

<img src="https://imgur.com/XN9fu0a.png"/>

Simply ssh with the current logged in user

`ssh MercerH@localhost`

<img src="https://imgur.com/ykyHgFH.png"/>

And you can see we are now a privleged user


```
THROWBACK.local\MercerH:pikapikachu7
JeffersD:Throwback2020 
```

Going back to bloodhound we can see that THROWBACK.LOCAL domain is trusted by CORPORATE.LOCAL

<img src="https://imgur.com/SlMTFHY.png"/>

