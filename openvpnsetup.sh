#!/bin/bash
#
# Express setup of OpenVPN server
# for Debian 10.x and Ubuntu 19.x and Later
# Originally by xl-tech https://github.com/xl-tech
# Modified by r3bers https://github.com/r3bers
#
# Version 0.21  March 2020
#
# Use only on fresh installed machine! It can rewrite your firewall rules
# or your current OpenVPN config (if you have it before).
#
# Script is licensed under the GNU General Public License v3.0
#
# Usage: just run openvpnsetup.sh :)
#

NET6="fd60:1:1:1::/64" #can generate yours at https://simpledns.plus/private-ipv6
NET4="192.168.100.0/24"
DNS1="192.168.100.1"
DNS2="fd60:1:1:1::1"
SSHPORT=22
export OPENVPN_DIR=/etc/openvpn
export EASYRSA=$OPENVPN_DIR/easy-rsa
export EASYRSA_PKI=$EASYRSA/pki

#Uncomment some options for less asking from console
#IP="0.0.0.0"
#PORT="udp 1194"
#CIPHER=AES-256-GCM
#IPV6E=1
NO_PASS="nopass" # Generete CA key without password

#check for root
IAM=$(whoami)
if [ "${IAM}" != "root" ]; then
    echo "You must be root to use this script"
    exit 1
fi

#check for tun/tap
if [ -c /dev/net/tun ]; then
    echo TUN/TAP is enabled
else
    echo TUN/TAP is disabled. Contact your VPS provider to enable it
    exit 1
fi

#enable IPv4 forwarding
if sysctl net.ipv4.ip_forward | grep 0; then
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward = 1" >>/etc/sysctl.conf
else
    echo "IPv4 forwarding is already enabled"
fi

#package install
deb_packages="openssl openvpn easy-rsa iptables netfilter-persistent iptables-persistent curl"

if cat /etc/*release | grep ^NAME | grep "Debian\|Ubuntu"; then
    apt-get install -y "$deb_packages"
    if hash ufw 2>/dev/null; then
        ufw disable
    else
        echo "UFW not installed"
    fi
else
    echo "Unsupported distro, sorry"
    exit 1
fi

#server settings
if [ -z "$IP" ]; then
    #internal IP
    IIP=$(hostname -I)
    #external IP
    EIP=$(curl -s checkip.dyndns.org | sed -e 's/.*Current IP Address: //' -e 's/<.*$//')
    #internal IPv6 with mask
    IIPv6=$(ip -6 addr | grep inet6 | awk -F '[ \t]+|/' '{print $3}' | grep -v ^::1 | grep -v ^fe80)

    echo "Select server IP to listen on (only used for IPv4):
    1) Internal IP - $IIP (in case you are behind NAT)
    2) External IP - $EIP
    3) External IPv6 - $IIPv6"
    read -r n
    case $n in
    1) IP=$IIP ;;
    2) IP=$EIP ;;
    3) IP=$IIPv6 ;;
    *) invalid option ;;
    esac
fi

if [ -z "$PORT" ]; then
    echo "Select server PORT to listen on:
    1) tcp 443 (recommended)
    2) udp 1194 (default)
    3) Enter manually (proto (lowercase!) port)"
    read -r n
    case $n in
    1) PORT="tcp 443" ;;
    2) PORT="udp 1194" ;;
    3)
        echo -n "Enter proto and port (like tcp 80 or udp 53): " &
        read -re PORT
        ;;
    *) invalid option ;;
    esac
fi

PORTN=$(echo "$PORT" | grep -o '[0-9]*')
PORTL=$(echo "$PORT" | grep -o '[a-z,A-Z]*')
PORTL6=$PORTL"6"

if [ -z "$CIPHER" ]; then
    echo "Select server cipher:
    1) AES-256-GCM (default for OpenVPN 2.4.x, not supported by Ubuntu Server 16.x)
    2) AES-256-CBC
    3) AES-128-CBC (default for OpenVPN 2.3.x)
    4) BF-CBC (insecure)"
    read -r n
    case $n in
    1) CIPHER=AES-256-GCM ;;
    2) CIPHER=AES-256-CBC ;;
    3) CIPHER=AES-128-CBC ;;
    4) CIPHER=BF-CBC ;;
    *) invalid option ;;
    esac
fi

if [ -z "$IPV6E" ]; then
    echo "Enable IPv6? (ensure that your machine have IPv6 support):
    1) Yes
    2) No"
    read -r n
    case $n in
    1) IPV6E=1 ;;
    2) IPV6E=0 ;;
    *) invalid option ;;
    esac
fi

echo "Check your selection"
echo "Server will listen on $IP"
echo "Server will listen on $PORT"
echo "Server will use $CIPHER cipher"
echo "IPv6 - $IPV6E (1 is enabled, 0 is disabled)"
read -rsp $'Press enter to continue...\n'

#create dirs and files
mkdir $EASYRSA
mkdir $OPENVPN_DIR/bundles
mkdir $OPENVPN_DIR/ccd

#copy easy-rsa
cp -a /usr/share/easy-rsa/* $EASYRSA

echo -e "set_var EASYRSA \"$EASYRSA\"
set_var EASYRSA_PKI \"$EASYRSA_PKI\"
set_var EASYRSA_CERT_EXPIRE 1825
set_var EASYRSA_CA_EXPIRE 3650
set_var EASYRSA_CRL_DAYS 180
set_var EASYRSA_DIGEST sha256
set_var EASYRSA_KEY_SIZE 2048
set_var EASYRSA_DN cn_only
set_var EASYRSA_REQ_COUNTRY \"RU\"
set_var EASYRSA_REQ_PROVINCE \"MSK\"
set_var EASYRSA_REQ_CITY \"Moscow\"
set_var EASYRSA_REQ_ORG \"MyVPN.org\"
set_var EASYRSA_REQ_OU \"MyVPN\"
set_var EASYRSA_REQ_CN \"MyVPN\"
set_var EASYRSA_REQ_EMAIL \"vpn@MyVPN.org\"
" >$EASYRSA/vars

#issue certs and keys
#init
"$EASYRSA/easyrsa" --batch init-pki

#ca
if ! "$EASYRSA/easyrsa" --batch build-ca ${NO_PASS}; then
    echo "Build CA failed"
    exit 1
fi

#crl
if ! "$EASYRSA/easyrsa" --batch gen-crl; then
    echo "Build CRL failed"
    exit 1
fi

#dh
"$EASYRSA/easyrsa" --batch gen-dh

#server
"$EASYRSA/easyrsa" --batch gen-req vpn-server nopass
if ! "$EASYRSA/easyrsa" --batch sign-req server vpn-server; then
    echo "Sign server cert request failed"
    exit 1
fi

#ta
openvpn --genkey --secret ${EASYRSA_PKI}/ta.key

#generate server config

#ipv6 part
if (("$IPV6E" == 1)); then

    #enable IPv6 forwarding
    if sysctl net.ipv6.conf.all.forwarding | grep 0; then
        sysctl -w net.ipv6.conf.all.forwarding=1
        echo "net.ipv6.conf.all.forwarding = 1" >>/etc/sysctl.conf
    else
        echo "IPv6 forwarding is already enabled"
    fi

    echo -e "#IPv6 config
server-ipv6 $NET6
proto $PORTL6
tun-ipv6
push tun-ipv6
push \042route-ipv6 2000::/3\042
push \042redirect-gateway ipv6\042
" >$OPENVPN_DIR/server.conf
else
    echo "local $IP" >$OPENVPN_DIR/server.conf
fi

#main part
{
    echo -e "port $PORTN
proto $PORTL
dev tun

#for cert revoke check
crl-verify $EASYRSA_PKI/crl.pem

server $NET4 255.255.255.0
topology subnet
push \042redirect-gateway def1 bypass-dhcp\042

#duplicate-cn

push \042dhcp-option DNS $DNS1\042
push \042dhcp-option DNS $DNS2\042

comp-lzo adaptive
push \042comp-lzo adaptive\042

#tun-mtu 1500
mtu-disc yes
mtu-test
mssfix 0
push \042mssfix 0\042
#push \042tun-mtu 1492\042

#management 0.0.0.0 7000 $OPENVPN_DIR/management-password

#duplicate-cn
keepalive 10 120
tls-timeout 160
hand-window 160

cipher $CIPHER
auth SHA256

#uncomment for 2.4.x feature to disable automatically negotiate in AES-256-GCM
ncp-disable

#max-clients 300

#user nobody
#group nobody

persist-key
persist-tun

status /var/log/openvpn-status.log
log-append /var/log/openvpn.log

verb 2
#reneg-sec 864000
mute 3
tls-server
#script-security 3

#buffers
sndbuf 1048576
rcvbuf 1048576
push \042sndbuf 1048576\042
push \042rcvbuf 1048576\042
"

    echo "<ca>"
    cat $EASYRSA_PKI/ca.crt
    echo "</ca>"

    echo "<cert>"
    cat $EASYRSA_PKI/issued/vpn-server.crt
    echo "</cert>"

    echo "<key>"
    cat $EASYRSA_PKI/private/vpn-server.key
    echo "</key>"

    # ta tls crypt OpenVPN 2.4.x
    echo "<tls-crypt>"
    cat $EASYRSA_PKI/ta.key
    echo "</tls-crypt>"

    echo "<dh>"
    cat $EASYRSA_PKI/dh.pem
    echo "</dh>"
} >>$OPENVPN_DIR/server.conf

#create iptables file
echo "*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:XL-Firewall-1-INPUT - [0:0]
-A INPUT -j XL-Firewall-1-INPUT
-A FORWARD -j XL-Firewall-1-INPUT
-A XL-Firewall-1-INPUT -p icmp --icmp-type any -s localhost -j ACCEPT
-A XL-Firewall-1-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A XL-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport $SSHPORT -j ACCEPT
-A XL-Firewall-1-INPUT -m state --state NEW -m $PORTL -p $PORTL --dport $PORTN -j ACCEPT
-A XL-Firewall-1-INPUT -i tun+ -j ACCEPT
-A XL-Firewall-1-INPUT -j REJECT --reject-with icmp-host-prohibited
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A POSTROUTING -s $NET4 -j SNAT --to-source $EIP
COMMIT" >/tmp/iptables

#create ip6tables file
echo "*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:XL-Firewall-1-INPUT - [0:0]
-A INPUT -j XL-Firewall-1-INPUT
-A FORWARD -j XL-Firewall-1-INPUT
-A XL-Firewall-1-INPUT -i lo -j ACCEPT
-A XL-Firewall-1-INPUT -p icmpv6 -j ACCEPT
-A XL-Firewall-1-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A XL-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport $SSHPORT -j ACCEPT
-A XL-Firewall-1-INPUT -m state --state NEW -m $PORTL -p $PORTL --dport $PORTN -j ACCEPT
-A XL-Firewall-1-INPUT -i tun+ -j ACCEPT
-A XL-Firewall-1-INPUT -j REJECT --reject-with icmp6-adm-prohibited
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A POSTROUTING -s $NET6 -j SNAT --to-source $IIPv6
COMMIT" >/tmp/ip6tables

#start services
cp /tmp/ip6tables /etc/iptables/rules.v6
cp /tmp/iptables /etc/iptables/rules.v4
systemctl enable netfilter-persistent &
systemctl start netfilter-persistent
systemctl enable openvpn@server &
systemctl start openvpn@server
systemctl restart netfilter-persistent

#generate client config

echo -e "client
dev tun
dev-type tun

#bind to interface if needed
#dev-node \042Ethernet\042

remote-cert-tls server
setenv opt tls-version-min 1.0 or-highest
#block local dns
setenv opt block-outside-dns
nobind

remote $EIP $PORTN $PORTL

cipher $CIPHER
auth SHA256

resolv-retry infinite
persist-key
persist-tun
comp-lzo
auth-nocache
verb 3
ping 10
tls-client
float" >$OPENVPN_DIR/client.ovpn

#generate bash script to create one-file config for clients

echo -e "#! /bin/bash
# Script to automate creating new OpenVPN clients
#
# H Cooper - 05/02/11
# Y Frolov - 08/06/16 - bundle config added (unified format)
# M Solovev - 15/01/20 - Migrate from pkitool EasyRSA 2.x to EasyRSA 3.x
# Usage: newclient.sh <common-name>

echo \042Script to generate unified config for OpenVPN Apps\042
echo \042sage: newclient.sh <common-name>\042

# Set vars
OPENVPN_DIR=$OPENVPN_DIR
EASY_RSA=\044OPENVPN_DIR/easy-rsa
EASYRSA_PKI=\044EASY_RSA/pki
BUNDLE_DIR=\044OPENVPN_DIR/bundles

# Either read the CN from \0441 or prompt for it
if [ -z \042\0441\042 ]
    then echo -n \042Enter new client common name (CN): \042
    read -er CN
else
    CN=\u00241
fi

# Ensure CN isn't blank
if [ -z \042\044CN\042 ]
    then echo \042You must provide a CN.\042
    exit 1
fi

# Check the CN doesn't already exist
if [ -f \044EASYRSA_PKI/issued/\044CN.crt ]
    then echo \042Error: certificate with the CN \044CN alread exists!\042
    echo \042    \044EASYRSA_PKI/issued/\044CN.crt\042
    exit
fi

# Generating Full Client package
\042\044EASY_RSA/easyrsa\042 build-client-full \044CN nopass

# Add all certs to unified client config file

# Default config for client
cp \044OPENVPN_DIR/client.ovpn \044BUNDLE_DIR/\044CN.ovpn

{
    # CA
    echo \042<ca>\042
    cat \044EASYRSA_PKI/ca.crt
    echo \042</ca>\042

    # Client cert
    echo \042<cert>\042
    cat \044EASYRSA_PKI/issued/\044CN.crt
    echo \042</cert>\042

    # Client key
    echo \042<key>\042
    cat \044EASYRSA_PKI/private/\044CN.key
    echo \042</key>\042

    # ta tls crypt OpenVPN 2.4.x
    echo \042<tls-crypt>\042
    cat \044EASYRSA_PKI/ta.key
    echo \042</tls-crypt>\042
} >> \044BUNDLE_DIR/\044CN.ovpn

echo \042COMPLETE! Copy the new unified config from here: $OPENVPN_DIR/bundles/\044CN.ovpn\042" >$OPENVPN_DIR/newclient.sh
chmod +x $OPENVPN_DIR/newclient.sh

echo "Setup is complete. Happy VPNing!"
echo "Use $OPENVPN_DIR/newclient.sh to generate client config"

exit 0
