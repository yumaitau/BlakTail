# Private service serving lab image (prove-private-services.sh): coordinator,
# Linux agent with kernel WireGuard tools, curl, and the Python API driver.
# rust:1.98-slim-bookworm (index digest; refresh: docker buildx imagetools inspect rust:1.98-slim-bookworm)
FROM rust@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,id=svclab-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=svclab-target,target=/src/target \
    cargo build --release -p blaktail-coord -p blaktaild \
 && mkdir -p /out \
 && cp target/release/blaktail-coord target/release/blaktaild /out/

# debian:bookworm-slim (index digest; refresh: docker buildx imagetools inspect debian:bookworm-slim)

FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl iproute2 iptables iputils-ping openssl procps python3 wireguard-tools \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/blaktail /data /certs \
 && chmod 0700 /var/lib/blaktail
COPY --from=build /out/ /usr/local/bin/
COPY deploy/homelab/svc-lab.py /usr/local/bin/svc-lab
ENTRYPOINT ["sleep"]
CMD ["infinity"]
