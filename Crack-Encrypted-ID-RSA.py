python /usr/share/john/ssh2john.py id_rsa >> hash && john --wordlist=/usr/share/wordlists/rockyou.txt --format=SSH hash

