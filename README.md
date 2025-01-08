Setting up an operator for Cartesi Coprocessor on Holesky:
* Requirements/assumptions: Ubuntu 24.04
* Install Eigenlayer CLI https://github.com/Layr-Labs/eigenlayer-cli/releases/tag/v0.12.0-beta
* Install Docker - https://docs.docker.com/engine/install/ubuntu/
* Generate a BLS key for your operator (generate a new one for this AVS if you already run existing AVS, don't reuse keys)
- ~/bin/eigenlayer keys create --key-type bls cartesi-operator 
- Note the BLS private key as shown
* 
