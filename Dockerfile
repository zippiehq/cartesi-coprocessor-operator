FROM rust:latest as base
RUN apt-get update && apt-get install -y protobuf-compiler clang libboost1.81-dev git

FROM base as operator-cache
WORKDIR /operator
COPY signer-eigen /operator/signer-eigen
COPY Cargo.toml /operator/Cargo.toml
COPY .cargo /operator/.cargo
COPY Cargo.lock /operator/Cargo.lock

RUN mkdir -p /operator/src && echo 'fn main() {}' > /operator/src/main.rs
RUN git config --global url."https://github.com/".insteadOf git@github.com: && \
    CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --features bls_signing

FROM base AS setup-operator-cache
WORKDIR /setup-operator
COPY setup-operator/Cargo.toml /setup-operator/Cargo.toml
COPY setup-operator/Cargo.lock /setup-operator/Cargo.lock

RUN mkdir -p /setup-operator/src && echo 'fn main() {}' > /setup-operator/src/main.rs
RUN cargo build --release

FROM base AS requests-test-cache
WORKDIR /requests-test
COPY requests-test/Cargo.toml /requests-test/Cargo.toml
COPY requests-test/Cargo.lock /requests-test/Cargo.lock

RUN mkdir -p /requests-test/src && echo 'fn main() {panic!()}' > /requests-test/src/main.rs
RUN cargo build --release

FROM rust:latest AS builder
RUN apt-get update && apt-get install -y protobuf-compiler clang libboost1.81-dev

WORKDIR /operator
COPY --from=operator-cache /operator/target /operator/target
COPY signer-eigen /operator/signer-eigen
COPY src /operator/src
COPY Cargo.toml /Cargo.lock /.cargo /operator/
RUN touch /operator/src/main.rs
RUN git config --global url."https://github.com/".insteadOf git@github.com: && \
    CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --features bls_signing

WORKDIR /setup-operator
COPY --from=setup-operator-cache /setup-operator/target /setup-operator/target
COPY setup-operator /setup-operator
RUN touch /setup-operator/src/main.rs
RUN cargo build --release

WORKDIR /requests-test
COPY --from=requests-test-cache /requests-test/target /requests-test/target
COPY requests-test /requests-test
RUN touch /requests-test/src/main.rs
RUN cargo build --release

FROM debian:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 ca-certificates curl netcat-traditional git lsof
COPY --from=builder /operator/target/release/cartesi-coprocessor-operator /operator/cartesi-coprocessor-operator
COPY --from=builder /setup-operator/target/release/setup-operator /operator/setup-operator
COPY --from=builder /requests-test/target/release/requests-test /operator/requests-test

RUN curl -L https://foundry.paradigm.xyz | bash
ARG TARGETARCH
RUN curl -LO https://github.com/ipfs/kubo/releases/download/v0.30.0/kubo_v0.30.0_linux-$TARGETARCH.tar.gz && \
    tar -xvzf kubo_v0.30.0_linux-$TARGETARCH.tar.gz && \
    bash kubo/install.sh && rm -rf kubo kubo_v0.30.0_linux-$TARGETARCH.tar.gz

COPY ./entrypoint.sh /entrypoint.sh
EXPOSE 3033
WORKDIR /operator
ENV IPFS_PATH=/data/ipfs
CMD ["/entrypoint.sh"]