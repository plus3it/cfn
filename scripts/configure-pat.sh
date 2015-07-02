#!/bin/bash
#
# Configure the instance to run as a Port Address Translator (PAT) to provide
# Internet connectivity to private instances.
#
# This script is based on the Amazon AWS script embedded in their NAT AMIs.
# Modified by Loren Gordon, hosted at:
# * https://github.com/lorengordon/cfn/scripts/configure-path.sh
#
# Changes from original:
# * Pass the eth interface as a parameter (but continue to default to eth0)
# * Die if unable to read the VPC_CIDR_RANGE from metadata
#

function log { logger -i -t "configure-pat" -s -- $1 2> /dev/console; }

function die {
    [ -n "$1" ] && log "$1"
    log "Configuration of PAT failed!"
    exit 1
}

# Sanitize PATH
PATH="/usr/sbin:/sbin:/usr/bin:/bin"

# Get ETH from first parameter, or default to eth0
ETH=${1:-eth0}

log "Determining the MAC address on ${ETH}..."
ETH_MAC=$(cat /sys/class/net/${ETH}/address) ||
    die "Unable to determine MAC address on ${ETH}."
log "Found MAC ${ETH_MAC} for ${ETH}."

VPC_CIDR_URI="http://169.254.169.254/latest/meta-data/network/interfaces/macs/${ETH_MAC}/vpc-ipv4-cidr-block"
log "Metadata location for vpc ipv4 range: ${VPC_CIDR_URI}"

VPC_CIDR_RANGE=$(curl --retry 3 --silent --fail ${VPC_CIDR_URI})
if [ $? -ne 0 ]; then
   die "Unable to retrieve VPC CIDR range from meta-data!"
else
   log "Retrieved VPC CIDR range ${VPC_CIDR_RANGE} from meta-data."
fi

log "Enabling PAT..."
sysctl -q -w net.ipv4.ip_forward=1 net.ipv4.conf.${ETH}.send_redirects=0 && (
   iptables -t nat -C POSTROUTING -o ${ETH} -s ${VPC_CIDR_RANGE} -j MASQUERADE 2> /dev/null ||
   iptables -t nat -A POSTROUTING -o ${ETH} -s ${VPC_CIDR_RANGE} -j MASQUERADE ) ||
       die "Failed to configure either sysctl or iptables."

sysctl net.ipv4.ip_forward net.ipv4.conf.${ETH}.send_redirects | log
iptables -n -t nat -L POSTROUTING | log

log "Configuration of PAT complete."
exit 0
