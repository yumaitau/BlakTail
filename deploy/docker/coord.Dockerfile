# BlakTail coordination server. TLS terminates inside the binary (rustls),
# so a load balancer can pass traffic through untouched.
FROM rust:1.98-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY config ./config
COPY blaktail-config ./blaktail-config
COPY blaktail-coord ./blaktail-coord
COPY blaktail-relay ./blaktail-relay
COPY blaktail-gateway ./blaktail-gateway
COPY blaktaild ./blaktaild
COPY blaktail-ios-wg ./blaktail-ios-wg
RUN cargo build --release -p blaktail-coord -p blaktail-config

FROM debian:bookworm-slim
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
