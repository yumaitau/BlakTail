# Self-contained relay lab image: coordinator, relay and Linux agent in one
# image, used by deploy/homelab/prove-relay-{nat,failover,wss}.sh. The build
# context is the tracked source tree streamed from `git ls-files`.
# rust:1.98-slim-bookworm (index digest; refresh: docker buildx imagetools inspect rust:1.98-slim-bookworm)
FROM rust@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=blaktail-relay-lab-target \
    cargo build --release -p blaktail-coord -p blaktail-relay -p blaktaild -p blaktail-config \
 && mkdir -p /out \
 && cp target/release/blaktail-coord target/release/blaktail-relay \
       target/release/blaktaild target/release/blaktail-config /out/

# debian:bookworm-slim (index digest; refresh: docker buildx imagetools inspect debian:bookworm-slim)

FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl iproute2 iptables iputils-ping openssl python3 \
      tcpdump wireguard-tools \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/blaktail /data \
 && chmod 0700 /var/lib/blaktail \
 && mv /usr/bin/wg /usr/local/bin/wg
COPY --from=build /out/ /usr/local/bin/
COPY deploy/homelab/relay-lab.py /usr/local/bin/relay-lab
RUN chmod 0755 /usr/local/bin/relay-lab
ENTRYPOINT []
CMD ["sleep", "infinity"]
