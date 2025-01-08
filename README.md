= Setting up an operator for Cartesi Coprocessor on Holesky =
* Requirements/assumptions: Ubuntu 24.04 - arm64 or amd64
* Install Eigenlayer CLI https://github.com/Layr-Labs/eigenlayer-cli/releases/tag/v0.12.0-beta
* Install Docker - https://docs.docker.com/engine/install/ubuntu/
* Set Docker up as a swarm manager in order to add Docker secrets

```docker swarm init``

* Generate a BLS key for your operator (generate a new one for this AVS if you already run existing AVS, don't reuse keys)

```~/bin/eigenlayer keys create --key-type bls cartesi-operator```

- Note the BLS private key as shown on screen
* Create a docker secret for the BLS key (paste it into this command)

```read blskey && echo -n "$blskey" | docker secret create operator1_bls_private_key - && blskey=```

* Create in an appropriate place the operator directory:

```mkdir -p /srv/cartesi-operator```

```cd /srv/cartesi-operator```

```curl -O https://raw.githubusercontent.com/zippiehq/cartesi-coprocessor-operator/refs/heads/main/docker-compose.yaml```

```mkdir -p operator1-ipfs operator1-snapshots operator1-db```
 
