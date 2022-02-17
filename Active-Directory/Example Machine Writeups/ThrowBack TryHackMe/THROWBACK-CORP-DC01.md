# TryHackMe-THROWBACK-CORP-01(10.200.34.118)

We can login with MercerH's credentials as this domain is trusted by THROWBACK.LOCAL but in order to do we need to run `autoroute` on DC because we cannot reach CORP domain through PROD

<img src="https://imgur.com/AJ34khU.png"/>

Here I downloaded meterpreter backdoor

<img src="https://imgur.com/WLCmUCo.png"/>

<img src="https://imgur.com/B4mKgOR.png"/>

Now we have to remove route from previous sessions which in my case is `6` so I will use autoroute and `SET CMD delelte, SET SESSION 6` and then run it. After that I will `SET CMD autoadd , SET SESSION 7` and run the module

<img src="https://imgur.com/PDcxGdc.png"/>

<img src="https://imgur.com/eM5RNf4.png"/>

<img src="https://imgur.com/iw48rok.png"/>

<img src="https://imgur.com/TXd0vHL.png"/>

<img src="https://imgur.com/I0xYoQo.png"/>

Add both the domain names in /etc/hosts file

<img src="https://imgur.com/kmfuRu9.png"/>

