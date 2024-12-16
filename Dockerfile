FROM rust:latest as builder
RUN apt-get update && apt-get install -y protobuf-compiler clang

WORKDIR /operator

COPY /signer-eigen /operator/signer-eigen
COPY /src /operator/src
COPY /Cargo.toml /operator/Cargo.toml
COPY /Cargo.lock /operator/Cargo.lock

WORKDIR /setup-operator
COPY /setup-operator /setup-operator

WORKDIR /operator
RUN git config --global url."https://github.com/".insteadOf git@github.com:
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --features bls_signing

WORKDIR /setup-operator
RUN cargo build --release --bin setup-operator

FROM debian:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 ca-certificates curl netcat-traditional 
COPY --from=builder /operator/target/release/cartesi-coprocessor-operator /operator/cartesi-coprocessor-operator
COPY --from=builder /setup-operator/target/release/setup-operator /operator/setup-operator

ARG TARGETARCH
RUN curl -LO https://github.com/ipfs/kubo/releases/download/v0.30.0/kubo_v0.30.0_linux-$TARGETARCH.tar.gz
RUN tar -xvzf kubo_v0.30.0_linux-$TARGETARCH.tar.gz
RUN bash kubo/install.sh && rm -rf kubo kubo_v0.30.0_linux-$TARGETARCH.tar.gz
COPY ./entrypoint.sh /entrypoint.sh

EXPOSE 3033
WORKDIR /operator
ENV IPFS_PATH=/data/ipfs
CMD ["/entrypoint.sh"]