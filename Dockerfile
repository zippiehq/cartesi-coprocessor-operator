FROM rust:latest as builder
RUN apt-get update && apt-get install -y protobuf-compiler clang

WORKDIR /lambda-api

COPY /src /lambda-api/src
COPY /Cargo.toml /lambda-api/Cargo.toml
WORKDIR /lambda-api
RUN git config --global url."https://github.com/".insteadOf git@github.com:
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --features bls_signing

FROM debian:bookworm
ARG ARCH=amd64


RUN apt-get update && apt-get install -y --no-install-recommends libssl3 ca-certificates curl netcat-traditional 
COPY --from=builder /lambda-api/target/release/cartesi-coprocessor-operator /lambda_api/cartesi-coprocessor-operator

RUN curl -LO https://github.com/ipfs/kubo/releases/download/v0.30.0/kubo_v0.30.0_linux-$ARCH.tar.gz
RUN tar -xvzf kubo_v0.30.0_linux-$ARCH.tar.gz
RUN bash kubo/install.sh && rm -rf kubo kubo_v0.30.0_linux-$ARCH.tar.gz
COPY ./entrypoint.sh /entrypoint.sh

EXPOSE 3033
WORKDIR /lambda_api
CMD ["/entrypoint.sh"]