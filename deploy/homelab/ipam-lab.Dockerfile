# IPv6 routing and renumbering lab image (prove-ipv6-renumber.sh): coordinator, Linux
# agent with kernel WireGuard tools, and the Python API driver in one image.
FROM rust:1.98-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,id=ipamlab-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=ipamlab-target,target=/src/target \
    cargo build --release -p blaktail-coord -p blaktaild -p blaktail-config \
 && mkdir -p /out \
 && cp target/release/blaktail-coord target/release/blaktaild target/release/blaktail-config /out/

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables iputils-ping openssl procps python3 wireguard-tools \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/blaktail /data /certs \
 && chmod 0700 /var/lib/blaktail
COPY --from=build /out/ /usr/local/bin/
COPY deploy/homelab/ipam-lab.py /usr/local/bin/ipam-lab
ENTRYPOINT ["sleep"]
CMD ["infinity"]
