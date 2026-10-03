# Homelab / prove image: Linux blaktaild with kernel WireGuard tools.
FROM rust:1.98-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY config ./config
COPY blaktail-config ./blaktail-config
COPY blaktail-coord ./blaktail-coord
COPY blaktail-relay ./blaktail-relay
COPY blaktail-relay-proto ./blaktail-relay-proto
COPY blaktaild ./blaktaild
COPY blaktail-ios-wg ./blaktail-ios-wg
RUN cargo build --release -p blaktaild -p blaktail-config

FROM debian:bookworm-slim
# Ubuntu 26.04 attaches host AppArmor profile `wg` to /usr/bin/wg even in
# unconfined containers, so keys outside /etc/wireguard get EACCES.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables iputils-ping wget wireguard-tools \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/blaktail \
 && chmod 0700 /var/lib/blaktail \
 && mv /usr/bin/wg /usr/local/bin/wg
# Ubuntu 26.04 attaches host AppArmor profile `wg` to /usr/bin/wg even in
# unconfined containers, so keys outside /etc/wireguard get EACCES.
COPY --from=build /src/target/release/blaktaild /usr/local/bin/blaktaild
COPY --from=build /src/target/release/blaktail-config /usr/local/bin/blaktail-config
VOLUME ["/var/lib/blaktail"]
ENTRYPOINT ["sleep"]
CMD ["infinity"]
