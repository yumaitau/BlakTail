# Australia-pinned UDP relay. Stateless; scale horizontally behind a UDP NLB.
FROM rust:1.98-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY config ./config
COPY blaktail-config ./blaktail-config
COPY blaktail-coord ./blaktail-coord
COPY blaktail-relay ./blaktail-relay
COPY blaktail-relay-proto ./blaktail-relay-proto
COPY blaktail-gateway ./blaktail-gateway
COPY blaktail-ingress ./blaktail-ingress
COPY blaktail-agentgw ./blaktail-agentgw
COPY blaktaild ./blaktaild
COPY blaktail-ios-wg ./blaktail-ios-wg
RUN cargo build --release -p blaktail-relay -p blaktail-config

FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 blaktail
COPY --from=build /src/target/release/blaktail-relay /usr/local/bin/blaktail-relay
COPY --from=build /src/target/release/blaktail-config /usr/local/bin/blaktail-config
USER blaktail
EXPOSE 3478/udp
ENTRYPOINT ["/usr/local/bin/blaktail-relay"]
