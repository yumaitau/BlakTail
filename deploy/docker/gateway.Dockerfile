# BlakTail browser remote-access gateway node: blaktaild owns the WireGuard
# interface and node credential; blaktail-gateway dials devices only over
# that overlay. Run guacd (guacamole/guacd) in the same network namespace
# for RDP. Start the agent first (`blaktaild up` / `run`), then the gateway.
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
RUN cargo build --release -p blaktaild -p blaktail-gateway -p blaktail-config

# debian:bookworm-slim (index digest; refresh: docker buildx imagetools inspect debian:bookworm-slim)

FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables wireguard-tools \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/blaktail \
 && chmod 0700 /var/lib/blaktail \
 && mv /usr/bin/wg /usr/local/bin/wg
COPY --from=build /src/target/release/blaktaild /usr/local/bin/blaktaild
COPY --from=build /src/target/release/blaktail-gateway /usr/local/bin/blaktail-gateway
COPY --from=build /src/target/release/blaktail-config /usr/local/bin/blaktail-config
VOLUME ["/var/lib/blaktail"]
EXPOSE 8443
ENTRYPOINT ["sleep"]
CMD ["infinity"]
