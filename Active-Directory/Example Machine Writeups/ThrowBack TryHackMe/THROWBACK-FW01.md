# TryHackMe-THROWBACK-FW01(10.200.34.138)

## NMAP

```
Nmap scan report for 10.200.34.138
Host is up, received echo-reply ttl 63 (0.18s latency).
Scanned at 2021-02-20 14:40:52 PKT for 219s
Not shown: 65531 filtered ports
Reason: 65531 no-responses
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey: 
|   4096 38:04:a0:a1:d0:e6:ab:d9:7d:c0:da:f3:66:bf:77:15 (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDN6yAJkDf3ePS4Etb1KKfEe6Az22BPADTvyCijKGexA0/xVVqwbhlLdXRf8lsGIyxOrEA/VZx7yq+iYL+tW8fnItuLaco6YTDJbtK8V0FQCFTyfCINNKH/jYABwG1i6TkZnaneAXKby8snChez7+r1Bz1fPzxne4PTrvBazH58jHV5A3y+xgskcZct8LnGnaib4LoAtXgd+t1sVjv+BHbpevCbSHNxhqb4S/Vsja2XTr37U1SXnst6xRTqRHal1ziq08Ijzxm17I5bUY6wRZRv01IZCWdE9JHaoVbkHtMOPMAsOsg99fXnb8I++jruuFWJbNQ26/1rwMqeaIslpAsKsFijCe5IbXwvKuzI6A9sM0IYObV+CevgYraQ7G4zx+WeBUIqu8dOt16n4suz33kaI17jbBdfSR6GxdT3ysqEsSkLd6p0HIR0JxIk5t7qGhG9KSvfsk42JUMyoocbK3tO8O/xInXPSuBWiohcGz0aJckVIOJuQSm8dkGRj62yOfzSyh9utWWu8Zi/dngRR6qOCMz538aQ/DReNEgqXl0Zn2roj42scFhidj4VgO0vhClotAmOZrFhu3wXc91ImkTdvApK7XcAQ4NGIt8kf0TylvHkV8T39zOB2uoFgITShRqHUQ6AnxwivFkdbdALT2IWh3CJRVD4Vwwog5L4ohsDjw==
53/tcp  open  domain   syn-ack ttl 63 (generic dns response: REFUSED)
80/tcp  open  http     syn-ack ttl 63 nginx
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://10.200.34.138/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
443/tcp open  ssl/http syn-ack ttl 63 nginx
|_http-favicon: Unknown favicon MD5: 5567E9CE23E5549E0FCD7195F3882816
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: pfSense - Login
| ssl-cert: Subject: commonName=pfSense-5f099cf870c18/organizationName=pfSense webConfigurator Self-Signed Certificate
| Subject Alternative Name: DNS:pfSense-5f099cf870c18
| Issuer: commonName=pfSense-5f099cf870c18/organizationName=pfSense webConfigurator Self-Signed Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-07-11T11:05:28
| Not valid after:  2021-08-13T11:05:28
| MD5:   fe06 fa47 4d83 8454 e67a 1840 7ea8 d101
| SHA-1: 672e 5f8f 9b28 7cad 5789 c5be cb1c f3f2 6c63 dfb2
|_-----END CERTIFICATE-----
```

### PORT 80 (HTTP)

<img src="https://imgur.com/gno4rk7.png"/>

We can see that there is a login page to pfsense control panel. I decided to try default credentials

<img src="https://imgur.com/YxPN6ai.png"/>

These credentials logged us in

<img src="https://imgur.com/9WiYRiq.png"/>

When logged in we can see `Diagnostics` tab and we see menu `Command Prompt`

<img src="https://imgur.com/sO9kOgD.png"/>

<img src="https://imgur.com/Ps3XdNV.png"/>

<img src="https://imgur.com/ECdK1pb.png"/>

We can see that commands will be executed as `root`

<img src="https://imgur.com/EpGlSAk.png"/>

Also php commands can be executed. I uploaded a `phpbash` which is like a backdoor having a full interactivev shell

`https://github.com/Arrexel/phpbash`

<img src="https://imgur.com/ge8QtTL.png"/>

<img src="https://imgur.com/wAdk1mU.png"/>

We can get the root flag in `/root/root.txt`

<img src="https://imgur.com/ZB6J78n.png"/>

We can find logs for in `/usr/local/www`

<img src="https://imgur.com/T65SEK1.png"/>

And we can get this this username and hash

`HumphreyW:1c13639dba96c7b53d26f7d00956a364`

I search for the log flag by running recusrive find command in `/var/log`

<img src="https://imgur.com/aLfc5dk.png"/>


Now the hash that we got for the user `HumphreyW` we need to crack it but we need to know what  type of hash it is so I went to `Name That Hash`

<img src="https://imgur.com/HHCPKGI.png"/>

It gave me a bunch of hash type for it so I checked for MD5 and MD4 that was a negative 

I started `hashcat` for NTLM (1000)

<img src="https://imgur.com/vecXikO.png"/>

And it was cracked 

<img src="https://imgur.com/lB3yanM.png"/>

