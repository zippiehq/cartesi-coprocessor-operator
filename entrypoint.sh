#!/bin/bash
if [ -z "$BLS_PRIVATE_KEY" ] && [ -e /run/secrets/bls_private_key ]; then
	BLS_PRIVATE_KEY=$(cat /run/secrets/bls_private_key)
fi
if [ -z "$BLS_PRIVATE_KEY" ]; then
 	echo "error: No BLS_PRIVATE_KEY set"
 	exit 1
fi
if [ ! -e /data/ipfs ]; then
  mkdir -p /data/ipfs
  IPFS_PATH=/data/ipfs ipfs init --profile=server
fi
IPFS_PATH=/data/ipfs ipfs config --bool Routing.AcceleratedDHTClient true
IPFS_PATH=/data/ipfs ipfs config Addresses.API /ip4/0.0.0.0/tcp/5001
IPFS_PATH=/data/ipfs ipfs config Addresses.Gateway /ip4/0.0.0.0/tcp/8080
IPFS_PATH=/data/ipfs ipfs config --json Peering.Peers '[{"ID": "bafzbeibhqavlasjc7dvbiopygwncnrtvjd2xmryk5laib7zyjor6kf3avm", "Addrs": ["/dnsaddr/elastic.dag.house"]}]'
if [ ! -z "$IPFS_PROVIDING" ]; then
	IPFS_PATH=/data/ipfs ipfs config --json Reprovider.Interval "0"
fi
if [ ! -z "$IPFS_GATEWAY_NOFETCH" ]; then
	IPFS_PATH=/data/ipfs ipfs config --json Gateway.NoFetch true
fi
if [ ! -z "$IPFS_DAEMON_OFFLINE" ]; then
	IPFS_PATH=/data/ipfs ipfs daemon --offline &
else
	IPFS_PATH=/data/ipfs ipfs daemon &
fi
IPFS_HOST="127.0.0.1"
IPFS_PORT="5001"

while true; do
   nc -z "$IPFS_HOST" "$IPFS_PORT"
   RET=$?
   echo $RET
   if [ x$RET = x0 ]; then
     break
   fi
   sleep 0.5
done
echo "IPFS up"

IPFS_URL=http://127.0.0.1:5001
if [ -z "$IPFS_WRITE_URL" ]; then
  IPFS_WRITE_URL=$IPFS_URL
fi
export IPFS_WRITE_URL
if [ -z "$SNAPSHOT_DIR" ]; then 
  mkdir -p /data/snapshot
  SNAPSHOT_DIR=/data/snapshot
fi
export SNAPSHOT_DIR
export IPFS_PATH
export BLS_PRIVATE_KEY
exec /operator/cartesi-coprocessor-operator