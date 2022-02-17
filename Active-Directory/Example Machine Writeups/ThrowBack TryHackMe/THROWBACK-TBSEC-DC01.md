# TryHackMe-THROWBACK-TBSEC-DC01

We have the credentials from the email

`TBSEC_GUEST:WelcomeTBSEC1!`

But in order to login I tried using `win-rm` and `ssh` both failed then I tried with RDP and got access

<img src="https://imgur.com/Ho5AHDs.png"/>

<img src="https://imgur.com/ampdw1G.png"/>

Run `powershell-empire --rest` and `starkiller`

<img src="https://imgur.com/wpzT0WF.png"/>

<img src="https://imgur.com/5lG3Rd1.png"/>

We have our listener ready

<img src="https://imgur.com/TqOQJnJ.png"/>

For setting a stager

<img src="https://imgur.com/aegimtS.png"/>

<img src="https://imgur.com/iTE4Rh6.png"/>

Now we need to deliver this bat file to target

<img src="https://imgur.com/fwnUaSg.png"/>

<img src="https://imgur.com/ITXp4LB.png"/>

<img src="https://imgur.com/Ofkg2vw.png"/>

Run the built in rubeus from starkiller

<img src="https://imgur.com/qQnZeMC.png"/>

<img src="https://imgur.com/5qlKOWh.png"/>

You can easily transfer the file by simpling clicking Download icon

<img src="https://imgur.com/Fgw8BZV.png"/>

<img src="https://imgur.com/nMxIDdx.png"/>

On running hashcat we will crack the hash

<img src="https://imgur.com/gQ8e57J.png"/>

We can now login through RDP with that account

<img src="https://imgur.com/dMtOKgt.png"/>
