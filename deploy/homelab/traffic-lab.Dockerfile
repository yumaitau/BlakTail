# Traffic reporting lab image (prove-traffic.sh): coordinator, Linux agent
# with kernel WireGuard tools and netcat, and the Python API driver.
FROM rust:1.98-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,id=trafficlab-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=trafficlab-target,target=/src/target \
    cargo build --release -p blaktail-coord -p blaktaild \
 && mkdir -p /out \
 && cp target/release/blaktail-coord target/release/blaktaild /out/

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates conntrack iproute2 iptables iputils-ping netcat-openbsd openssl procps python3 wireguard-tools \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/blaktail /data /certs \
 && chmod 0700 /var/lib/blaktail
COPY --from=build /out/ /usr/local/bin/
COPY --chmod=0755 deploy/homelab/traffic-lab.py /usr/local/bin/traffic-lab
ENTRYPOINT ["sleep"]
CMD ["infinity"]
