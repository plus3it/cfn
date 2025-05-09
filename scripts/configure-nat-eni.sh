#!/bin/bash
#
# configure-nat-eni.sh
#
# This script is designed to attach an Elastic Network Interface to
# a NAT instance.
#
# Written by Loren Gordon, hosted at:
# * https://github.com/plus3it/cfn/blob/master/scripts/configure-nat-eni.sh
#
# Inspired by:
# * http://www.cakesolutions.net/teamblogs/making-aws-nat-instances-highly-available-without-the-compromises
#
# Script will look for an ENI with a tag `TAG_KEY` that matches the
# `TAG_KEY` on the instance. e.g. Both the ENI and the instance
# must have a tag of `TAG_KEY` and the value must be the same.
# `TAG_KEY` defaults to 'Name', but can be passed as the first
# parameter to the script.
#
# Pre-requisites:
# 1. Instance must have a tag where `key="TAG_KEY"`.
# 2. ENI must have a tag where `key="TAG_KEY"`.
# 3. The `value` of both those tags must be the same.
# 4. The instance must have an IAM EC2 Role that grants these permissions:
#        {
#            "Version" : "2012-10-17",
#            "Statement": [ {
#                "Effect": "Allow",
#                "Action": [
#                    "ec2:AttachNetworkInterface",
#                    "ec2:DetachNetworkInterface",
#                    "ec2:DescribeNetworkInterfaces",
#                    "ec2:DescribeInstances"
#                ],
#                "Resource": "*"
#            } ]
#        }
# 5. The `awscli` package must be installed.

function log { logger -i -t "configure-nat-eni" -s -- "$1" 2> /dev/console; }

function die {
    [ -n "$1" ] && log "$1"
    log "Failed to attach ENI"'!'
    exit 1
}

# Sanitize PATH
PATH="/usr/sbin:/sbin:/usr/bin:/bin:/usr/local/bin"

TAG_KEY="${1:-Name}"
DEVICE_TYPE="${2:-eth}" # The type of network interface recognized by the system, i.e. 'eth'
DEVICE_INDEX="${3:-1}"  # The device to attach to, i.e. 1=eth1, 2=eth2, etc

RETRY_DELAY=1   # retry every <delay> seconds
TIMER_NIC_DISCOVERY=20  # wait this many seconds before failing


INSTANCE_ID=$(curl --retry 3 --silent --fail http://169.254.169.254/latest/meta-data/instance-id) || \
    die "Could not get instance id."
log "Found instance id '${INSTANCE_ID}'."

AVAILABILITY_ZONE=$(curl --retry 3 --silent --fail http://169.254.169.254/latest/meta-data/placement/availability-zone) || \
    die "Could not get availability zone."
log "Found availability zone '${AVAILABILITY_ZONE}'."

REGION=$(curl --retry 3 --silent --fail http://169.254.169.254/latest/dynamic/instance-identity/document | awk -F\" '/region/ {print $4}') || \
    die "Could not get region."
log "Found region '${REGION}'."

export AWS_DEFAULT_REGION=${REGION}

log "Determining the value of tag '${TAG_KEY}'..."
TAG_VALUE=$(aws ec2 describe-instances \
    --filters "Name=instance-id,Values=${INSTANCE_ID}" \
    --query 'Reservations[0].Instances[0].Tags[?Key==`'"${TAG_KEY}"'`].Value' \
    --output text)
if [ -z "${TAG_VALUE}" ]; then
    die "Could not get the tag value from the instance."
else
    log "Found tag value '${TAG_VALUE}'."
fi

log "Determining the ENI to attach to the instance..."
ENI=$(aws ec2 describe-network-interfaces \
    --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
              "Name=availability-zone,Values=${AVAILABILITY_ZONE}" \
    --query "NetworkInterfaces[0].{ \
              NetworkInterfaceId: NetworkInterfaceId, \
              InstanceId: Attachment.InstanceId, \
              AttachmentId: Attachment.AttachmentId}")
if [ -z "${ENI}" ]; then
    die "Could not find a matching ENI."
fi

ENI_ID=$(echo "${ENI}" | awk -F\" '/NetworkInterfaceId/ {print $4}')
if [ -z "${ENI}" ]; then
    die "Could not get the ENI ID."
else
    log "Found ENI ID '${ENI_ID}'."
fi

ENI_ATTACHMENT=$(echo "${ENI}" | awk -F\" '/AttachmentId/ {print $4}')
if [ -n "${ENI_ATTACHMENT}" ]; then
    ENI_INSTANCE=$(echo "${ENI}" | awk -F\" '/InstanceId/ {print $4}')
    if [ "${ENI_INSTANCE}" == "${INSTANCE_ID}" ]; then
        log "ENI '${ENI_ID} is attached to this instance already. Exiting..."
        exit 0
    fi
    log "ENI '${ENI_ID}' is attached to instance ${ENI_INSTANCE}. Detaching now..."
    aws ec2 detach-network-interface --attachment-id "${ENI_ATTACHMENT}" || \
        aws ec2 detach-network-interface --attachment-id "${ENI_ATTACHMENT}" --force || \
            die "Could not detach network interface."
    log "Successfully detached the network interface. Proceeding..."
fi

log "Attaching ENI '${ENI_ID}' to this instance..."
delay=15
timer=180
while true; do
    if [[ $timer -le 0 ]]; then
        die "Timer expired before ENI attached successfully."
    fi
    aws ec2 attach-network-interface --network-interface-id "${ENI_ID}" \
        --instance-id "${INSTANCE_ID}" --device-index "${DEVICE_INDEX}"  && break  # break if ENI attached successfully
    log "ENI attachment failed. Trying again in $delay second(s). Will timeout if not attached within $timer second(s)."
    sleep $delay
    timer=$(( timer-delay ))
done

log "ENI '${ENI_ID}' is attached to this instance."

ETH="${DEVICE_TYPE}${DEVICE_INDEX}"
log "Waiting for '${ETH}' network interface to be discovered by the system..."
delay=$RETRY_DELAY
timer=$TIMER_NIC_DISCOVERY
while true; do
    if [[ $timer -le 0 ]]; then
        die "Timer expired before network interface acquired MAC address."
    fi
    ETH_MAC=$(cat /sys/class/net/"${ETH}"/address 2> /dev/null) && break  # break loop if MAC was found
    log "Not found yet. Trying again in $delay second(s). Will timeout if not reachable within $timer second(s)."
    sleep $delay
    timer=$(( timer-delay ))
done

log "Found ${ETH} MAC '${ETH_MAC}'."

log "Waiting for '${ETH}' network interface to get an IP address..."
delay=$RETRY_DELAY
timer=$TIMER_NIC_DISCOVERY
while true; do
    if [[ $timer -le 0 ]]; then
        die "Timer expired before network interface acquired IP address."
    fi
    IP_ADDRESS=$(ip addr show dev "${ETH}" 2> /dev/null | awk '/inet /{ sub(/\/.*$/,"",$2); print $2 }')
    if [[ -n "${IP_ADDRESS}" ]]; then
        break  # break loop if IP was found
    fi
    log "Not found yet. Trying again in $delay second(s). Will timeout if not reachable within $timer second(s)."
    sleep $delay
    timer=$(( timer-delay ))
done

log "Got IP '${IP_ADDRESS}' on ${ETH}."

# Add route to metadata IP address via the new interface
# The logic for RTABLE is derived from the ec2-net-utils scripts created by Amazon
RTABLE=$(( 10000 + DEVICE_INDEX ))
METADATA_IP="169.254.169.254"
log "Adding route to ${METADATA_IP} via device ${ETH}..."
ip route add "${METADATA_IP}" dev "${ETH}" table "${RTABLE}" 2>&1 | log
ip route add "${METADATA_IP}" dev "${ETH}" metric "${RTABLE}" 2>&1 | log

log "ENI attachment successful"'!'
exit 0
