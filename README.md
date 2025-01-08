# Setting up an operator for Cartesi Coprocessor on Holesky

* Requirements/assumptions: Ubuntu 24.04 - arm64 or amd64
* Install Eigenlayer CLI https://github.com/Layr-Labs/eigenlayer-cli/releases/tag/v0.12.0-beta
* Install Docker - https://docs.docker.com/engine/install/ubuntu/

* Create in an appropriate place the operator directory:

```mkdir -p /srv/cartesi-operator```

```cd /srv/cartesi-operator```

```curl -O https://raw.githubusercontent.com/zippiehq/cartesi-coprocessor-operator/refs/heads/main/docker-compose.yaml```

```mkdir -p operator1-ipfs operator1-snapshots operator1-db```

* Generate a BLS key for your operator (generate a new one for this AVS if you already run existing AVS, don't reuse keys)

```~/bin/eigenlayer keys create --key-type bls cartesi-operator```

- Note the BLS private key as shown on screen

* Store the secret so the Create a docker secret for the BLS key (paste it into this command)

```read blskey && echo -n "$blskey" > operator1_bls_private_key && blskey=```
 
* Bring it up
```docker compose up -d --wait```

* Download a machine to test with, ctrl-c when it says "ready"

```while true; do curl -X POST "http://127.0.0.1:3033/ensure/bafybeihpo6pncx7hyf26v6vszb25q4spszigxkfc4fxvamfzpy5b2bjydm/11084eeb3de8d6ad262736d1f59b129fc9c134ab52248d39c2c920facafe8403/289182342"; sleep 60; done```

* Run a sample task:

```curl -X POST -H "X-Ruleset: B819BA4c5d2b64d07575ff4B30d3e0Eca219BFd5" -H "X-Max-Ops: 1" -H "X-Console-Putchar: true"  -d "test2" -v http://127.0.0.1:3033/classic/11084eeb3de8d6ad262736d1f59b129fc9c134ab52248d39c2c920facafe8403```

* Process more concurrent computation jobs: set MAX_THREADS_NUMBER environment variable to a higher integer amount (currently 3 by default)
