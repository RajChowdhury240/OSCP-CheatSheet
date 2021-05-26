#!/bin/bash

BLACK="\033[30m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
PINK="\033[35m"
CYAN="\033[36m"
WHITE="\033[37m"
NORMAL="\033[0;39m"

# Fix Missing tput error for dumb shells
export TERM=linux

# Quick Linux Local Enumeration Script 
# v1.1

cat << "EOF"
                       .
                        `:.
                          `:.
                  .:'     ,::
                 .:'      ;:'
                 ::      ;:'
                  :    .:'
                   `.  :.
          _________________________
         :                         :
     ,---:      HighOn.Coffee      :
    : ,'"`:       Modified         :'
    `.`.  `:                     :'
      `.`-._:                   :
        `-.__`.               ,' 
    ,--------`"`-------------'--------.
     `"--.__                   __.--"'
            `""-------------""'

EOF

sleep 1.4

printf "URL: $GREEN http://highon.coffee $NORMAL \n"

sleep 0.4

printf "Version: $YELLOW 1.0 $NORMAL \n"

sleep 0.4

printf "Twitter: $BLUE @HighOn_Coffee $NORMAL \n"
sleep 0.2
printf "Author: $BLUE @Arr0way $NORMAL \n"

sleep 0.2
printf "Modified: $BLUE @kevthehermit $NORMAL \n"

sleep 0.4
printf "Disclaimer: \n"
printf "\n"
printf "$RED HighOn.Coffee is not responsible for misuse or for any damage that you may cause! \n
 You agree that you use this software at your own risk. $NORMAL  \n"

printf "\n"
printf "\n"

sleep 3

printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#' 
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Linux Version" 
printf "\n"
printf "$BLUE"
printf "##" 
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/bin/cat /etc/issue;
printf "\n" 
/bin/cat /etc/*-release

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Kernel Info"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/bin/uname -ar

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Network Info"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"


/bin/cat /etc/sysconfig/network 2>/dev/null
printf "/n"
/sbin/ifconfig -a 2>/dev/null
printf "\n"
/bin/cat /etc/resolv.conf

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Netstat"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

netstat -antup
ss -tuan 2>/dev/null

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED File System Info"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/df -h

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Mounted File Systems with Pretty Output"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/df -h

mount | column -t

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /etc/fstab File Contents"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/cat /etc/fstab


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /etc/passwd File Contents"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/bin/cat /etc/passwd


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /etc/shadow File Contents"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/bin/cat /etc/shadow

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /etc/group File Contents"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/bin/cat /etc/group


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /etc/sudoers File Contents"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/cat /etc/sudoers

sudo -l

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Config Files with keyword 'password'"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/usr/bin/find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Log Files with keyword 'password'"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"


find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED SUID/SGID Files and Directories"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

#/usr/bin/find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
/usr/bin/find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED World Writable Directories"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/usr/bin/find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED World Writable Files"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/usr/bin/find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Files Owned by Current User"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

#/usr/bin/find / -prune -o -wholename '/proc/*' -user $(whoami) 2>/dev/null
/usr/bin/find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -user $(whoami) \) -exec ls -l '{}' ';' 2>/dev/null


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /home and /root Permissions"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/ls -ahlR /home/
/bin/ls -ahlR /root/ 


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Logged on Users"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/usr/bin/w


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Last Logged on Users"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/usr/bin/last

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Processes Running as root"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/ps -ef | /bin/grep root

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED All Processes"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/ps -aux


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Installed Packages for RHEL / Debian Based Systems"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

# Enumarate CentOS / Ubuntu Boxes 
# This is not a great way of ID'ing a box, but I'm being lazy


printf "\n"
/usr/bin/dpkg -l

printf "\n"
/usr/bin/rpm -qa

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED CentOS / RHEL Services that start at Boot"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

chkconfig --list | grep $(runlevel | awk '{ print $2}'):on

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED List of init Scripts aka System Services"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

printf "\n"
printf "$BLUE## $RED /etc/inet.d"
printf "\n"
printf "$NORMAL"
ls /etc/init.d/ 2>/dev/null
printf "\n"
printf "$BLUE## $RED /etc/xinet.d"
printf "\n"
printf "$NORMAL"
ls /etc/xinetd.d/ 2>/dev/null


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Linux Services Status"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

service --status-all 2>/dev/null

printf "\n"

systemctl --no-pager list-units --type service 2>/dev/null

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Cron Jobs"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"



ls -la /etc/cron* 2>/dev/null

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /etc/crontab"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

cat /etc/crontab 2>/dev/null


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Installed Tools"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"



which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "$NORMAL"

printf "\n More Linux enumeration commands can be found at: $BLUE https://highon.coffee/docs/linux-commands  \n"

printf "\n $RED So long, and thanks for all the fish... \n $NORMAL"

printf "\n"
