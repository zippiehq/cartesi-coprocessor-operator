# dependency cache
FROM rust:1.85.1 AS cache
RUN apt-get update && apt-get install -y protobuf-compiler clang libboost1.81-dev git lua5.4

# cache operator node depenedencies
WORKDIR /operator
COPY signer-eigen /operator/signer-eigen
COPY Cargo.toml /operator/Cargo.toml
COPY .cargo /operator/.cargo
COPY Cargo.lock /operator/Cargo.lock

RUN mkdir -p /operator/src && echo 'fn main() {}' > /operator/src/main.rs
RUN git config --global url."https://github.com/".insteadOf git@github.com: && \
    CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --features bls_signing

# cache setup-operator depenedencies
WORKDIR /setup-operator
COPY setup-operator/Cargo.toml /setup-operator/Cargo.toml
COPY setup-operator/Cargo.lock /setup-operator/Cargo.lock

RUN mkdir -p /setup-operator/src && echo 'fn main() {}' > /setup-operator/src/main.rs
RUN cargo build --release

# cache requests-tests depenedencies
WORKDIR /requests-test
COPY requests-test/Cargo.toml /requests-test/Cargo.toml
COPY requests-test/Cargo.lock /requests-test/Cargo.lock

RUN mkdir -p /requests-test/src && echo 'fn main() {panic!()}' > /requests-test/src/main.rs
RUN cargo build --release

# source code builder
FROM rust:1.85.1 AS builder
RUN apt-get update && apt-get install -y protobuf-compiler clang libboost1.81-dev
COPY --from=cache /usr/local/cargo /usr/local/cargo
COPY --from=cache /operator/target /operator/target
COPY --from=cache /setup-operator/target /setup-operator/target
COPY --from=cache /requests-test/target /requests-test/target

# build operator node
WORKDIR /operator
COPY signer-eigen /operator/signer-eigen
COPY src /operator/src
COPY Cargo.toml /Cargo.lock /.cargo /operator/
RUN touch /operator/src/main.rs
RUN git config --global url."https://github.com/".insteadOf git@github.com: && \
    CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --features bls_signing

# build setup-operator
WORKDIR /setup-operator
COPY setup-operator /setup-operator
RUN touch /setup-operator/src/main.rs
RUN cargo build --release

# build requests-test
WORKDIR /requests-test
COPY requests-test /requests-test
RUN touch /requests-test/src/main.rs
RUN cargo build --release

# final installation
FROM debian:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 ca-certificates curl netcat-traditional git lsof
COPY --from=builder /operator/target/release/cartesi-coprocessor-operator /operator/cartesi-coprocessor-operator
COPY --from=builder /setup-operator/target/release/setup-operator /operator/setup-operator
COPY --from=builder /requests-test/target/release/requests-test /operator/requests-test

# third-party tools
RUN curl -L https://foundry.paradigm.xyz | bash
RUN curl -sSfL https://raw.githubusercontent.com/layr-labs/eigenlayer-cli/master/scripts/install.sh | sh -s -- v0.12.0-beta3
ARG TARGETARCH
RUN curl -LO https://github.com/ipfs/kubo/releases/download/v0.30.0/kubo_v0.30.0_linux-$TARGETARCH.tar.gz && \
    tar -xvzf kubo_v0.30.0_linux-$TARGETARCH.tar.gz && \
    bash kubo/install.sh && rm -rf kubo kubo_v0.30.0_linux-$TARGETARCH.tar.gz

COPY ./entrypoint.sh /entrypoint.sh
EXPOSE 3033
WORKDIR /operator
ENV IPFS_PATH=/data/ipfs
CMD ["/entrypoint.sh"]