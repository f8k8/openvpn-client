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
#      REVISION: 2.0
#===============================================================================

set -o nounset                              # Treat unset variables as an error

### ----------------------------------------------------
### Functions for setting up iptables rules
### ----------------------------------------------------

### reset_iptables: Reset the iptables so nothing can get access by default
# Arguments:
#   iptables / ip6tables - Which iptables to reset
reset_iptables() {
	local IPT=$1

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
}

### setup_iptables: Setup the iptables
# Arguments:
#   iptables / ip6tables - Which iptables to set up
#   docker network - The local docker network
#   dns1 - DNS server 1
#   dns2 - DNS server 2
#   info_file - The info file to write debug config data to
setup_iptables() {
    local IPT=$1
    local docker_network=$2
	local dns1=$3
	local dns2=$4
    local info_file=$5

    echo "iptables info" >${info_file}
    echo "docker_network: ${docker_network}" >>${info_file}
    echo "VPN ports: ${vpnport}" >>${info_file}
    [[ -n "${dns1}" ]] && echo "DNS Server 1: ${dns1}" >>${info_file}
    [[ -n "${dns2}" ]] && echo "DNS Server 2: ${dns2}" >>${info_file}

    # Basically, the idea of these rules are:
    # - By default, block everything
    # - Accept packets on established or related connections
    # - Allow output to our specified DNS servers on port 53 so that we can lookup our VPN IP by name
    # - Allow output on our VPN port (defaults to 1194)
    # - Allow output on tun devices (which will be our VPN tunnel once it's established)
    # - Allow input & output to the local docker network

    # Because we block everything by default, nothing should be able to access anything until we output
    # on one of our allowed connections (DNS server / port, VPN port, tun adapter)
    # Once we've tried to access one of these, the rest of the packets will be allowed by the 
    # conntrack (connection tracking) rules

    # Allow established and related packets
    ${IPT} -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ${IPT} -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow access to DNS
    [[ -n "${dns_server1}" ]] &&
        ${IPT} -A OUTPUT -d ${dns1} -p tcp -m tcp --dport 53 -j ACCEPT &&
        ${IPT} -A OUTPUT -d ${dns1} -p udp -m udp --dport 53 -j ACCEPT &&
        echo "nameserver $dns1" >>/etc/resolv.conf
    [[ -n "${dns_server2}" ]] &&
        ${IPT} -A OUTPUT -d ${dns2} -p tcp -m tcp --dport 53 -j ACCEPT &&
        ${IPT} -A OUTPUT -d ${dns2} -p udp -m udp --dport 53 -j ACCEPT &&
        echo "nameserver $dns2" >>/etc/resolv.conf

    # Allow output from source VPN port and to destination VPN port
    while read -r port; do
        ${IPT} -A OUTPUT -p udp -m udp --sport ${port} -j ACCEPT
        ${IPT} -A OUTPUT -p udp -m udp --dport ${port} -j ACCEPT
        ${IPT} -A OUTPUT -p tcp -m tcp --dport ${port} -j ACCEPT
        echo "Added VPN Port: ${port}" >>${info_file}
    done <<< "${vpnport}"

    # Allow output on all tun devices
    ${IPT} -A OUTPUT -o tun+ -j ACCEPT

    # Allow output to the docker network
    ${IPT} -A OUTPUT -d ${docker_network} -j ACCEPT
	
	# Also allow input from the docker network
	${IPT} -A INPUT -s ${docker_network} -j ACCEPT
}

### firewall: Firewall all output not DNS/VPN that's not over the VPN connection
# Arguments:
#   none
firewall() {
    # Get the local network address (IPv4 and IPv6) that we're running on
    local docker_network="$(ip -o addr show dev eth0 | awk '$3 == "inet" {print $4}')"
    local docker_network6="$(ip -o addr show dev eth0 | awk '$3 == "inet6" {print $4; exit}')"

    # Reset resolv.conf
    echo "nameserver 127.0.0.1" >/etc/resolv.conf

	# Reset iptables
	[[ ${docker_network6} ]] && reset_iptables ip6tables
	[[ ${docker_network} ]] && reset_iptables iptables

    # Setup iptables
    [[ "${ip6_enabled:-""}" = "1" ]] && [[ ${docker_network6} ]] && setup_iptables ip6tables ${docker_network6} ${dns_server1_6} ${dns_server2_6} ${firewall_info6}
    [[ ${docker_network} ]] && setup_iptables iptables ${docker_network} ${dns_server1} ${dns_server2} ${firewall_info} 
}

### allow_host_network6: Allow input from the host network to the docker network
# Arguments:
#   network - The host network CIDR
allow_host_network6() {
    local network="$1"
    local defaultNetwork="$(ip -6 route | awk '/default/{print $3}')"
    ip -6 route | grep -q "${network}" ||
        ip -6 route add to ${network} via ${defaultNetwork} dev eth0
    ip6tables -A INPUT -s ${network} -j ACCEPT

    # Add the info to the route info file
    echo "Allowing input from ${network} to ${defaultNetwork}" >> ${firewall_info6}
}

### allow_host_network: Allow input from the host network to the docker network
# Arguments:
#   network - The host network CIDR
allow_host_network() {
    local network="$1"
    local defaultNetwork="$(ip route | awk '/default/ {print $3}')"
    ip route | grep -q "${network}" ||
        ip route add to ${network} via ${defaultNetwork} dev eth0
    iptables -A INPUT -d ${network} -j ACCEPT

    # Add the info to the route info file
    echo "Allowing input from ${network} to ${defaultNetwork}" >> ${firewall_info}
}

### ----------------------------------------------------
### Functions for generating the config file for OpenVPN
### ----------------------------------------------------

### remove_persist_tun: Removes the persist-tun option from the config
###                     We need to do this so that OpenVPN can recreate the
###                     tun device if the link goes down or we receive a SIGUSR1
remove_persist_tun() {
	sed -i 's/^persist-tun/;persist-tun/g' ${conf}
}

### add_cert_auth_config: Setup auth password for accessing certificate
# Arguments:
#   passwd - Password to access the cert
add_cert_auth_config() {
    local passwd="$1"
    grep -q "^${passwd}\$" ${cert_auth} || {
        echo "$passwd" >${cert_auth}
    }
    chmod 0600 ${cert_auth}
    grep -q "^askpass ${cert_auth}\$" ${conf} || {
        sed -i '/askpass/d' ${conf}
        echo "askpass ${cert_auth}" >>${conf}
    }
}

### dns: setup openvpn client DNS
# Arguments:
#   none)
add_dns_config() {
    sed -i '/down\|up/d; /resolv-*conf/d; /script-security/d' ${conf}
    echo "# This updates the resolvconf with dns settings" >>${conf}
    echo "script-security 2" >>${conf}
    echo "up /etc/openvpn/up.sh" >>${conf}
    echo "down /etc/openvpn/down.sh" >>${conf}
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

    echo "client" >${conf}
    echo "dev tun" >>${conf}
    echo "proto udp" >>${conf}
    for i in $(sed 's/:/ /g' <<< ${server}); do
        echo "remote $i ${vpnport}" >>${conf}
    done
    [[ ${server} =~ : ]] && echo "remote-random" >>${conf}
    echo "resolv-retry infinite" >>${conf}
    echo "keepalive 10 60" >>${conf}
    echo "nobind" >>${conf}
    echo "persist-key" >>${conf}
    [[ "${CIPHER:-""}" ]] && echo "cipher $CIPHER" >>${conf}
    [[ "${AUTH:-""}" ]] && echo "auth ${auth}" >>${conf}
    echo "tls-client" >>${conf}
    echo "remote-cert-tls server" >>${conf}
    echo "auth-user-pass ${auth}" >>${conf}
    echo "comp-lzo" >>${conf}
    echo "verb 1" >>${conf}
    echo "reneg-sec 0" >>${conf}
    echo "redirect-gateway def1" >>${conf}
    echo "disable-occ" >>${conf}
    echo "fast-io" >>${conf}
    echo "ca ${cert}" >>${conf}
    [[ $(wc -w <<< $pem) -eq 1 ]] && echo "crl-verify $pem" >>${conf}

    echo "$user" >${auth}
    echo "$pass" >>${auth}
    chmod 0600 ${auth}
}

### ----------------------------------------------------

### get_dns_servers6: helper function to set the two DNS server addresses from arguments
# Arguments:
#   dns_server1 - The first DNS server to use
#   dns_server2 - The second DNS server to use
get_dns_servers6() {
    dns_server1_6="${1:-""}"
    dns_server2_6="${2:-""}"
}

### get_dns_servers: helper function to set the two DNS server addresses from arguments
# Arguments:
#   dns_server1 - The first DNS server to use
#   dns_server2 - The second DNS server to use
get_dns_servers() {
    dns_server1="${1:-""}"
    dns_server2="${2:-""}"
}

### usage: Display help text
# Arguments:
#   none
usage() {
    local RC="${1:-0}"
    echo "Usage: ${0##*/} [-opt] [command]
Options (fields in '[]' are optional, '<>' are required):
    -h This help
    -c '<passwd>' Configure an authentication password to open the cert
                required arg: '<passwd>'
                <passwd> password to access the certificate file
	-D '<dns_server1_6>[;dns_server2_6]' Specify DNS servers to use for IPv6
    -d '<dns_server1>[;dns_server2]' Specify DNS servers to use for IPv4
    -R '<network>' CIDR IPv6 network (IE fe00:d34d:b33f::/64)
                required arg: '<network>'
                <network> add a route and allow input from host network
    -r '<network>' CIDR IPv4 network (IE 192.168.1.0/24)
                required arg: '<network>'
                <network> add a route and allow input from host network
    -v '<server;user;password[;port]>' Configure OpenVPN
                required arg: '<server>;<user>;<password>'
                <server> to connect to (multiple servers are separated by :)
                <user> to authenticate as
                <password> to authenticate with
                optional arg: [port] to use, instead of default
	-6 Enable IPv6

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
input_auth="$dir/vpn.auth"

# OpenVPN config
input_conf="$dir/vpn.conf"

# Certificate
cert="$dir/vpn-ca.crt"

# Certificate auth file
input_cert_auth="$dir/vpn.cert_auth"

# Generated files
# ---------------

# The final auth file to use
auth="$dir/.vpn.auth"

# The final OpenVPN config to use
conf="$dir/.vpn.conf"

# The final certificate auth file to use
cert_auth="$dir/.vpn.cert_auth"

# Information about the firewall
firewall_info="$dir/.firewall"
firewall_info6="$dir/.firewall6"

### ----------------------------------------------------
### Main Script
### ----------------------------------------------------

# Use default conf and cert, or look for the one existing .conf/.ovpn and .cert
[[ -f ${input_conf} ]] || { [[ $(ls -d $dir/*|egrep '\.(conf|ovpn)$' 2>&-|wc -w) -eq 1 \
            ]] && input_conf="$(ls -d $dir/* | egrep '\.(conf|ovpn)$' 2>&-)"; }
[[ -f ${cert} ]] || { [[ $(ls -d $dir/* | egrep '\.ce?rt$' 2>&- | wc -w) -eq 1 \
            ]] && cert="$(ls -d $dir/* | egrep '\.ce?rt$' 2>&-)"; }

[[ -w ${firewall_info} ]] && rm ${firewall_info}
[[ -w ${firewall_info6} ]] && rm ${firewall_info6}

# Fetch any parameters from the environment
cert_auth_password="${CERT_AUTH:-""}"

# IPv6
ip6_enabled="${IP6_ENABLED:-"0"}"
host_network6="${ROUTE6:-""}"
dns_server1_6="${DNS_SERVER1_6:-""}"
dns_server2_6="${DNS_SERVER2_6:-""}"

# IPv4
host_network="${ROUTE:-""}"
dns_server1="${DNS_SERVER1:-""}"
dns_server2="${DNS_SERVER2:-""}"

vpnport=""

# Copy the input VPN config if it exists
# We do this because if VPN environment variable or -v is specified, new conf and auth files are
# written, so don't overwrite the originals
[[ -r ${input_auth} ]] && cp ${input_auth} ${auth}
[[ -r ${input_conf} ]] && cp ${input_conf} ${conf}
[[ -r ${input_cert_auth} ]] && cp ${input_cert_auth} ${cert_auth}

# Use values from environment variables if set
[[ "${VPN:-""}" ]] && eval generate_vpn_config $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $VPN)

while getopts ":hc:D:d:R:r:v:6" opt; do
    case "$opt" in
        h) usage ;;
        c) cert_auth_password="$OPTARG" ;;
		D) eval get_dns_servers6 $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $OPTARG) ;;
        d) eval get_dns_servers $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $OPTARG) ;;
        R) host_network6="$OPTARG" ;;
        r) host_network="$OPTARG" ;;
        v) eval generate_vpn_config $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $OPTARG) ;;
		6) ip6_enabled="1" ;;
        "?") echo "Unknown option: -$OPTARG"; usage 1 ;;
        ":") echo "No argument value for option: -$OPTARG"; usage 2 ;;
    esac
done
shift $(( OPTIND - 1 ))

# At this point, we should have a config file set up
[[ ! -r ${conf} ]] && echo "ERROR: No OpenVPN config specified" && exit 13

# Add the DNS and cert auth options to the generated VPN config
add_dns_config
[[ "${cert_auth_password:-""}" ]] && add_cert_auth_config

# Remove the persist-tun option so OpenVPN can recreate the tunnel if needed
remove_persist_tun

# Make sure we have a port for the VPN specified
# If no port was passed but is empty, try and read it from ${input_conf}
[[ -z "${vpnport}" ]] &&
    vpnport="$(awk '/^remote / && NF ~ /^[0-9]*$/ {print $NF}' ${conf} | grep ^ || echo 1194)"

# Make sure vpnport doesn't contain duplicates
vpnport=$(echo "${vpnport}" | sort -u)

# Setup the firewall
firewall

# Setup the holes to our host network if needed
[[ "${ip6_enabled:-""}" = "1" ]] && [[ "${host_network6:-""}" ]] && allow_host_network6 ${host_network6}
[[ "${host_network:-""}" ]] && allow_host_network ${host_network}

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
    [[ -e ${conf} ]] || { echo "ERROR: VPN not configured!"; sleep 120; }
    [[ -e ${cert} ]] || grep -q '<ca>' ${conf} ||
        { echo "ERROR: VPN CA cert missing!"; sleep 120; }
    exec sg vpn -c "openvpn --cd $dir --config ${conf}"
fi
