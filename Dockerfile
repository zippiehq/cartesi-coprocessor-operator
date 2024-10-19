FROM rust:latest as builder
RUN apt-get update && apt-get install -y protobuf-compiler clang

WORKDIR /lambda-api

COPY /src /lambda-api/src
COPY /Cargo.toml /lambda-api/Cargo.toml
WORKDIR /lambda-api
RUN git config --global url."https://github.com/".insteadOf git@github.com:
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --features bls_signing

FROM debian:bookworm
RUN apt-get update && apt-get install -y libssl3 ca-certificates
COPY --from=builder /lambda-api/target/release/lambda_api /lambda_api/lambda_api

EXPOSE 3033
WORKDIR /lambda_api
CMD ["/lambda_api/lambda_api"]