# Lab image for deploy/homelab/prove-public-ingress.sh: coordinator, Linux
# blaktaild (kernel WireGuard) and blaktail-ingress in one image.
FROM rust:1.98-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p blaktail-coord -p blaktaild -p blaktail-ingress -p blaktail-config \
 && mkdir -p /out \
 && cp target/release/blaktail-coord target/release/blaktaild target/release/blaktail-ingress target/release/blaktail-config /out/

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl iproute2 iptables iputils-ping openssl procps python3 wireguard-tools \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/blaktail && chmod 0700 /var/lib/blaktail \
 && mv /usr/bin/wg /usr/local/bin/wg
COPY --from=build /out/ /usr/local/bin/
ENTRYPOINT ["sleep"]
CMD ["infinity"]
