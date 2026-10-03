# Shared image for the prove-*.sh labs added for the routing, connector, sshd,
# upgrade and concurrency proofs: coordinator and Linux agent built from the
# working tree, plus the network tools the labs drive (iptables in both nft
# and legacy modes, tcpdump, OpenSSH, dig, netcat, Python).
FROM rust:1.98-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,id=labs-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=labs-target,target=/src/target \
    cargo build --release -p blaktail-coord -p blaktaild \
 && mkdir -p /out \
 && cp target/release/blaktail-coord target/release/blaktaild /out/

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl dnsutils iproute2 iptables iputils-ping netcat-openbsd \
      openssh-client openssh-server openssl procps python3 tcpdump wireguard-tools \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/blaktail /data /certs /run/sshd \
 && chmod 0700 /var/lib/blaktail
COPY --from=build /out/ /usr/local/bin/
ENTRYPOINT ["sleep"]
CMD ["infinity"]
