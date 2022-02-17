# TryHackMe-THROWBACK-SEC-BREACH

Now we need to run this tool `LeetLinked`

<img src="https://imgur.com/mAolcZu.png"/>

This returned as a list of emails

<img src="https://imgur.com/0nO4zCc.png"/>

But we need to convert the format which found from a note in dosierk's documents. So we will be using `namely` to generate emails in a proper format using names we found from `leetlinked`

<img src="https://imgur.com/pQdjR2d.png"/>

<img src="https://imgur.com/juRsXJg.png"/>

Now this in HRE format but there are other formats as well

<img src="https://imgur.com/isgepKW.png"/>

<img src="https://imgur.com/xUI3yGl.png"/>

In this I generated a list of potential emails now only thing left for us to do is to visit `breachgtfo.local` and check for breached emails

<img src="https://imgur.com/xQzcFI9.png"/>

We can use `wfuzz` to check for response length 

<img src="https://imgur.com/X7hwkzj.png"/>

We get the same amount of Characters so we can hide `4950` and see if there are characters with a length other than that

<img src="https://imgur.com/gGyaXgq.png"/>

And we have found a request with different characters

<img src="https://imgur.com/O1dwJ5z.png"/>

Now if we try to login on thier corporate mail 

<img src="https://imgur.com/TYCSw0s.png"/>s