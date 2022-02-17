# TryHackMe-THROWBACK-MAIL (10.200.34.232 )

## NMAP

```
Nmap scan report for 10.200.34.232                                                                                     
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                            
|   2048 3b:b1:4c:b7:3f:fc:3e:ec:83:0f:0e:db:bf:25:9a:01 (RSA)
|   256 76:62:f3:eb:94:08:bc:a8:34:53:44:4d:ec:ac:87:f1 (ECDSA)
|_  256 0b:80:aa:78:66:34:43:09:db:99:98:e1:99:7e:a8:b0 (ED25519)
80/tcp  open  http     Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Throwback Hacks - Login                                     
|_Requested resource was src/login.php                                    
143/tcp open  imap     Dovecot imapd (Ubuntu)                             
|_imap-capabilities: Pre-login IDLE LOGINDISABLEDA0001 SASL-IR more capabilities have ID post-login listed OK IMAP4rev1 STARTTLS ENABLE LOGIN-REFERR
ALS LITERAL+                         
| ssl-cert: Subject: commonName=ip-10-40-119-232.eu-west-1.compute.internal
| Subject Alternative Name: DNS:ip-10-40-119-232.eu-west-1.compute.internal
| Not valid before: 2020-07-25T15:51:57                                   
|_Not valid after:  2030-07-23T15:51:57                                   
|_ssl-date: TLS randomness does not represent time                        
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)                             
|_imap-capabilities: Pre-login IDLE SASL-IR more capabilities have ID post-login IMAP4rev1 OK AUTH=PLAINA0001 listed ENABLE LOGIN-REFERRALS LITERAL+
| ssl-cert: Subject: commonName=ip-10-40-119-232.eu-west-1.compute.internal
| Subject Alternative Name: DNS:ip-10-40-119-232.eu-west-1.compute.internal
| Not valid before: 2020-07-25T15:51:57                                   
|_Not valid after:  2030-07-23T15:51:57                                   
|_ssl-date: TLS randomness does not represent time            
```

### PORT 80 (HTTP)

<img src="https://imgur.com/d9e7tsk.png"/>

We can login with the guest credentials which are

`tbhguest:WelcomeTBH1!`

<img src="https://imgur.com/LOmrerX.png"/>

We can get our first flag form the inbox

<img src="https://imgur.com/CWVwFgT.png"/>

Going to `Addresses` tab we can see a list of usernames and emails

<img src="https://imgur.com/jRZY2gn.png"/>

Now intercept the login request in order to start bruteforce attack so we can use these parameters in `hyda`

<img src="https://imgur.com/OupyinM.png"/>

We have the usernames but don't have the passwords but it was told that some accounts might use weak credentials so I crafted some passwords

```
Summer2020
Management2020
Management2018
Password2020
ThrowbackHacks2020
Throwback202
Password123
Winter2020
Winter2018
Spring2020
Winter2019
Summer2018
Summer2019
```

<img src="https://imgur.com/kZWj0R8.png"/>


```
login: PeanutbutterM   password: Summer2020
login: DaviesJ   password: Management2018
login: GongoH   password: Summer2020
login: MurphyF   password: Summer2020
login: JeffersD   password: Summer2020
```

We logged in as guest again because it had the email addresses of all users and we wanted to send to everyone 

<img src="https://imgur.com/feDfq4O.png"/>

Generate a staged  payload for catching reverse shell through metasploit

<img src="https://imgur.com/wIg0ddO.png"/>

<img src="https://imgur.com/9S6i6Ph.png"/>

Attatched the payload in email

<img src="https://imgur.com/yPr7R71.png"/>

After sending the email I wait for some time a got a metepreter session

<img src="https://imgur.com/jFJpTyr.png"/>

<img src="https://imgur.com/G1Y5yPg.png"/>