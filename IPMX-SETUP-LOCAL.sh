#!/bin/sh
export IPMX_REGISTRY_ADDRESS=127.0.0.1
export IPMX_REGISTRY_PORT=8443
export IPMX_SENDER_ADDRESS=127.0.0.1
export IPMX_SENDER_PORT=5010
export IPMX_RECEIVER_ADDRESS=127.0.0.1
export IPMX_RECEIVER_PORT=5010
export IPMX_VENDOR=Local

# Make sure we are at the top level where this script is located
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -d "IPMX_VENDOR_$IPMX_VENDOR" ]; then
    mkdir -p "IPMX_VENDOR_$IPMX_VENDOR"
fi

if [ ! -f "IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders.guid" ]; then
    cp ipmx-test-senders-NONE.guid "IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders.guid"
fi

if [ ! -f "IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders-NONE.guid" ]; then
    cp ipmx-test-senders-NONE.guid "IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-senders-NONE.guid"
fi

if [ ! -f "IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers.guid" ]; then
    cp ipmx-test-receivers-NONE.guid "IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers.guid"
fi

if [ ! -f "IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers-NONE.guid" ]; then
    cp ipmx-test-receivers-NONE.guid "IPMX_VENDOR_$IPMX_VENDOR/ipmx-test-receivers-NONE.guid"
fi
