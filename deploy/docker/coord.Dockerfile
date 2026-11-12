# BlakTail coordination server. TLS terminates inside the binary (rustls),
# so a load balancer can pass traffic through untouched.
# rust:1.98-slim-bookworm (index digest; refresh: docker buildx imagetools inspect rust:1.98-slim-bookworm)
FROM rust@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS build
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
RUN cargo build --release -p blaktail-coord -p blaktail-config

# debian:bookworm-slim (index digest; refresh: docker buildx imagetools inspect debian:bookworm-slim)

FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 blaktail \
 && mkdir -p /data && chown blaktail:blaktail /data
COPY --from=build /src/target/release/blaktail-coord /usr/local/bin/blaktail-coord
COPY --from=build /src/target/release/blaktail-config /usr/local/bin/blaktail-config
COPY --chown=blaktail:blaktail --chmod=0755 deploy/docker/coord-entrypoint.sh /usr/local/bin/coord-entrypoint
USER blaktail
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8443
ENTRYPOINT ["coord-entrypoint"]
CMD ["serve"]
