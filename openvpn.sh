#!/usr/bin/env bash
#===============================================================================
#          FILE: openvpn.sh
#
#         USAGE: ./openvpn.sh
#
#   DESCRIPTION: Entrypoint for openvpn docker container
#
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: David Personette (dperson@gmail.com),
#  ORGANIZATION:
#       CREATED: 09/28/2014 12:11
#      REVISION: 1.0
#===============================================================================

set -o nounset                              # Treat unset variables as an error

### ----------------------------------------------------
### Functions for setting up iptables rules
### ----------------------------------------------------

### setup_iptables: setup the iptables
# Arguments:
#   iptables / ip6tables
#   docker network
setup_iptables() {
	local IPT=$1
	local docker_network=$2
        local info_file=$3

	echo "iptables info" >$info_file
        echo "docker_network: ${docker_network}" >>$info_file
	echo "VPN ports: $vpnport" >>$info_file
	[[ -n "${dns_server1}" ]] && echo "DNS Server 1: ${dns_server1}" >>$info_file
	[[ -n "${dns_server2}" ]] && echo "DNS Server 2: ${dns_server2}" >>$info_file

	# Basically, the idea of these rules are:
	# - By default, block everything
	# - Accept packets on established or related connections
	# - Allow output to our specified DNS servers so that we can lookup our VPN IP by name
	# - Allow output on port 53 - this lets us use a DNS by IP even if dns_server1 & dns_server2 aren't specified
	# - Allow output on our VPN port (defaults to 1194)
	# - Allow output on tun devices (which will be our VPN tunnel once it's established)
	# - Allow output to the local docker network

	# Because we block everything by default, nothing should be able to access anything until we output
	# on one of our allowed connections (DNS server / port, VPN port, tun adapter or docker_network).
	# Once we've tried to access one of these, the rest of the packets will be allowed by the 
	# conntrack (connection tracking) rules

	# Delete non-default chains
	${IPT} -X

	# Flush built-in chains
	${IPT} -F

	# Set default policy for built-in chains to drop packets
	${IPT} -P INPUT DROP
    ${IPT} -P OUTPUT DROP
    ${IPT} -P FORWARD DROP

	# Allow loopback interface to do anything
    ${IPT} -A INPUT -i lo -j ACCEPT
    ${IPT} -A OUTPUT -o lo -j ACCEPT

	# Allow established and related packets
    ${IPT} -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ${IPT} -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow access to DNS
	[[ -n "${dns_server1}" ]] &&
		${IPT} -A OUTPUT -d ${dns_server1} -p tcp -m tcp --dport 53 -j ACCEPT &&
		${IPT} -A OUTPUT -d ${dns_server1} -p udp -m udp --dport 53 -j ACCEPT &&
		echo "nameserver $dns_server1" >>/etc/resolv.conf
	[[ -n "${dns_server2}" ]] &&
		${IPT} -A OUTPUT -d ${dns_server2} -p tcp -m tcp --dport 53 -j ACCEPT &&
		${IPT} -A OUTPUT -d ${dns_server2} -p udp -m udp --dport 53 -j ACCEPT &&
		echo "nameserver $dns_server2" >>/etc/resolv.conf

	# Allow output from source VPN port and to destination VPN port
	while read -r port; do
	    ${IPT} -A OUTPUT -p udp -m udp --sport $port -j ACCEPT
	    ${IPT} -A OUTPUT -p udp -m udp --dport $port -j ACCEPT
	    ${IPT} -A OUTPUT -p tcp -m tcp --dport $port -j ACCEPT

		echo "Added VPN Port: ${port}" >>$info_file


	done <<< "$vpnport"

	# Allow output on all tun devices
    ${IPT} -A OUTPUT -o tun+ -j ACCEPT

	# Allow output to the docker network
    ${IPT} -A OUTPUT -d ${docker_network} -j ACCEPT
}

### firewall: firewall all output not DNS/VPN that's not over the VPN connection
# Arguments:
#   none)
firewall() {
	# Get the local network address (IPv4 and IPv6) that we're running on
	local docker_network="$(ip -o addr show dev eth0 | awk '$3 == "inet" {print $4}')"
	local docker6_network="$(ip -o addr show dev eth0 | awk '$3 == "inet6" {print $4; exit}')"

	# Reset resolv.conf
	echo "nameserver 127.0.0.1" >/etc/resolv.conf

	# Setup iptables
	[[ ${docker6_network} ]] && setup_iptables ip6tables ${docker6_network} ${firewall_info6}
	[[ ${docker_network} ]] && setup_iptables iptables ${docker_network} ${firewall_info}
}

### return_route6: add a route from the docker network to your host
# Arguments:
#   network) a CIDR specified network range
return_route6() {
	local network="$1"
	local defaultNetwork="$(ip -6 route | awk '/default/{print $3}')"
    ip -6 route | grep -q "$network" ||
        ip -6 route add to $network via $defaultNetwork dev eth0
    ip6tables -A OUTPUT --d $network -j ACCEPT

	# Add the info to the route info file
    echo "Route added to $network via $defaultNetwork" >> $firewall_info6
}

### return_route: add a route from the docker network to your host
# Arguments:
#   network) a CIDR specified network range
return_route() {
	local network="$1"
	local defaultNetwork="$(ip route | awk '/default/ {print $3}')"
    ip route | grep -q "$network" ||
        ip route add to $network via $defaultNetwork dev eth0
    iptables -A OUTPUT --d $network -j ACCEPT

    echo "Route added to $network via $defaultNetwork" >> $firewall_info
}

### ----------------------------------------------------
### Functions for generating the config file for OpenVPN
### ----------------------------------------------------

### cert_auth: setup auth passwd for accessing certificate
# Arguments:
#   passwd) Password to access the cert
# Return: conf file that supports certificate authentication
add_cert_auth_config() {
	local passwd="$1"
    grep -q "^${passwd}\$" $cert_auth || {
        echo "$passwd" >$cert_auth
    }
    chmod 0600 $cert_auth
    grep -q "^askpass ${cert_auth}\$" $conf || {
        sed -i '/askpass/d' $conf
        echo "askpass $cert_auth" >>$conf
    }
}

### dns: setup openvpn client DNS
# Arguments:
#   none)
add_dns_config() {
    sed -i '/down\|up/d; /resolv-*conf/d; /script-security/d' $conf
    echo "# This updates the resolvconf with dns settings" >>$conf
    echo "script-security 2" >>$conf
    echo "up /etc/openvpn/up.sh" >>$conf
    echo "down /etc/openvpn/down.sh" >>$conf
}

### vpn: overwrites the VPN conf with our parameters
# Arguments:
#   server) VPN server
#   user) user name on VPN
#   pass) password on VPN
#   port) port to connect to VPN (optional)
generate_vpn_config() { 
	local server="$1" 
	local user="$2" 
	local pass="$3" 
	vpnport="${4:-1194}" 
	local i
	local pem="$(\ls $dir/*.pem 2>&-)"

    echo "client" >$conf
    echo "dev tun" >>$conf
    echo "proto udp" >>$conf
    for i in $(sed 's/:/ /g' <<< $server); do
        echo "remote $i $vpnport" >>$conf
    done
    [[ $server =~ : ]] && echo "remote-random" >>$conf
    echo "resolv-retry infinite" >>$conf
    echo "keepalive 10 60" >>$conf
    echo "nobind" >>$conf
    echo "persist-key" >>$conf
    echo "persist-tun" >>$conf
    [[ "${CIPHER:-""}" ]] && echo "cipher $CIPHER" >>$conf
    [[ "${AUTH:-""}" ]] && echo "auth $AUTH" >>$conf
    echo "tls-client" >>$conf
    echo "remote-cert-tls server" >>$conf
    echo "auth-user-pass $auth" >>$conf
    echo "comp-lzo" >>$conf
    echo "verb 1" >>$conf
    echo "reneg-sec 0" >>$conf
    echo "redirect-gateway def1" >>$conf
    echo "disable-occ" >>$conf
    echo "fast-io" >>$conf
    echo "ca $cert" >>$conf
    [[ $(wc -w <<< $pem) -eq 1 ]] && echo "crl-verify $pem" >>$conf

    echo "$user" >$auth
    echo "$pass" >>$auth
    chmod 0600 $auth
}

### ----------------------------------------------------

### get_dns_servers: helper function to set the two DNS server addresses from arguments
get_dns_servers() {
	$dns_server1="$1"
	$dns_server2="$2"
}

### usage: Help
# Arguments:
#   none)
# Return: Help text
usage() {
	local RC="${1:-0}"
    echo "Usage: ${0##*/} [-opt] [command]
Options (fields in '[]' are optional, '<>' are required):
    -h          This help
    -c '<passwd>' Configure an authentication password to open the cert
                required arg: '<passwd>'
                <passwd> password to access the certificate file
    -d  '<dns_server1>[;dns_server2]' Specify DNS servers to use
    -R '<network>' CIDR IPv6 network (IE fe00:d34d:b33f::/64)
                required arg: '<network>'
                <network> add a route to (allows replies once the VPN is up)
    -r '<network>' CIDR network (IE 192.168.1.0/24)
                required arg: '<network>'
                <network> add a route to (allows replies once the VPN is up)
    -v '<server;user;password[;port]>' Configure OpenVPN
                required arg: '<server>;<user>;<password>'
                <server> to connect to (multiple servers are separated by :)
                <user> to authenticate as
                <password> to authenticate with
                optional arg: [port] to use, instead of default

The 'command' (if provided and valid) will be run instead of openvpn
" >&2
    exit $RC
}

### ----------------------------------------------------
### Default config
### ----------------------------------------------------

dir="/vpn"

# Input config files
# ------------------

# VPN auth file
auth="$dir/vpn.auth"

# Certificate
cert="$dir/vpn-ca.crt"

# Certificate auth file
cert_auth="$dir/vpn.cert_auth"

# OpenVPN config
input_conf="$dir/vpn.conf"

# Generated files
# ---------------

# The final OpenVPN config to use
conf="$dir/.vpn.conf"

# Information about the firewall
firewall_info="$dir/.firewall"
firewall_info6="$dir/.firewall6"

### ----------------------------------------------------
### Main Script
### ----------------------------------------------------

# Use default conf and cert, or look for the one existing .conf/.ovpn and .cert
[[ -f $input_conf ]] || { [[ $(ls -d $dir/*|egrep '\.(conf|ovpn)$' 2>&-|wc -w) -eq 1 \
            ]] && input_conf="$(ls -d $dir/* | egrep '\.(conf|ovpn)$' 2>&-)"; }
[[ -f $cert ]] || { [[ $(ls -d $dir/* | egrep '\.ce?rt$' 2>&- | wc -w) -eq 1 \
            ]] && cert="$(ls -d $dir/* | egrep '\.ce?rt$' 2>&-)"; }

rm $firewall_info
rm $firewall_info6

# Get parameters
cert_auth_password="${CERT_AUTH:-""}"
route_6_network="${ROUTE6:-""}"
route_network="${ROUTE:-""}"
dns_server1="${DNS_SERVER1:-""}"
dns_server2="${DNS_SERVER2:-""}"
vpnport=""

# Copy the input VPN config if it exists
[[ -r $input_conf ]] && cp $input_conf $conf

# Use values from environment variables if set
[[ "${VPN:-""}" ]] && eval generate_vpn_config $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $VPN)

while getopts ":hc:d:R:r:v:" opt; do
    case "$opt" in
        h) usage ;;
        c) cert_auth_password="$OPTARG" ;;
		d) eval get_dns_servers $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $OPTARG) ;;
        R) route_6_network "$OPTARG" ;;
        r) route_network "$OPTARG" ;;
        v) eval generate_vpn_config $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $OPTARG) ;;
        "?") echo "Unknown option: -$OPTARG"; usage 1 ;;
        ":") echo "No argument value for option: -$OPTARG"; usage 2 ;;
    esac
done
shift $(( OPTIND - 1 ))

# At this point, we should have a config file set up
[[ ! -r $conf ]] && echo "ERROR: No OpenVPN config specified" && exit 13

# Add the DNS and cert auth options to the generated VPN config
add_dns_config
[[ "${cert_auth_password:-""}" ]] && add_cert_auth_config

# Make sure we have a port for the VPN specified
# If no port was passed but is empty, try and read it from $input_conf
[[ -z "$vpnport" ]] &&
    vpnport="$(awk '/^remote / && NF ~ /^[0-9]*$/ {print $NF}' $conf | grep ^ || echo 1194)"

# Make sure vpnport doesn't contain duplicates
vpnport=$(echo "$vpnport" | sort -u)

# Setup the firewall
firewall

# Setup the holes to our host network if needed
[[ "${route_6_network:-""}" ]] && return_route6 $route_6_network
[[ "${route_network:-""}" ]] && return_route $route_network

if [[ $# -ge 1 && -x $(which $1 2>&-) ]]; then
    echo "Running command: $@"
    exec "$@"
elif [[ $# -ge 1 ]]; then
    echo "ERROR: command not found: $1"
    exit 13
elif ps -ef | egrep -v 'grep|openvpn.sh' | grep -q openvpn; then
    echo "Service already running, please restart container to apply changes"
else
    mkdir -p /dev/net
    [[ -c /dev/net/tun ]] || mknod -m 0666 /dev/net/tun c 10 200
    [[ -e $conf ]] || { echo "ERROR: VPN not configured!"; sleep 120; }
    [[ -e $cert ]] || grep -q '<ca>' $conf ||
        { echo "ERROR: VPN CA cert missing!"; sleep 120; }
    exec sg vpn -c "openvpn --cd $dir --config $conf"
fi
