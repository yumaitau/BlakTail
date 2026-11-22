# Post-quantum PSK lab image (prove-post-quantum.sh): coordinator, Linux
# agent with kernel WireGuard tools, and the Python API driver in one image.
# rust:1.98-slim-bookworm (index digest; refresh: docker buildx imagetools inspect rust:1.98-slim-bookworm)
FROM rust@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,id=pqlab-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=pqlab-target,target=/src/target \
    cargo build --release -p blaktail-coord -p blaktaild -p blaktail-config \
 && mkdir -p /out \
 && cp target/release/blaktail-coord target/release/blaktaild target/release/blaktail-config /out/

# debian:bookworm-slim (index digest; refresh: docker buildx imagetools inspect debian:bookworm-slim)

FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables iputils-ping openssl procps python3 wireguard-tools \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/blaktail /data /certs \
 && chmod 0700 /var/lib/blaktail
COPY --from=build /out/ /usr/local/bin/
COPY deploy/homelab/pq-lab.py /usr/local/bin/pq-lab
ENTRYPOINT ["sleep"]
CMD ["infinity"]
