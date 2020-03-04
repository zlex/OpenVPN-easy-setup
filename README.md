# OpenVPN-easy-setup
Bash script for easy and fast OpenVPN server deploy

For  Debian 10.x and Ubuntu 19.x and later
Use only on fresh installed machine. It will rewrite your iptables and OpenVPN configuration.

Features:
- Setup new server with one command in a couple of minutes;
- Creates client config in unified format;
- Choose of port and protocol;
- Choose of cipher;
- IPv6 support.

Usage: ./openvpnsetup.sh 

Before enabling IPv6 support ensure that your machine have IPv6 address.
Notes:
  - iptables rule allow port 22 tcp (ssh) by default, if you have sshd on another port modify script before execution.
  - Ports and Nets can be configured in vars on top of script.

After script is complete you can create client config files in unified format with /etc/openvpn/newclient.sh script.
Usage: ./newclient.sh clientname
Config file will be saved to /etc/openvpn/bundles/clientname.ovpn and it ready to use (even on mobile device).





