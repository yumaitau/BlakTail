# Self-contained relay lab image: coordinator, relay and Linux agent in one
# image, used by deploy/homelab/prove-relay-{nat,failover,wss}.sh. The build
# context is the tracked source tree streamed from `git ls-files`.
FROM rust:1.98-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=blaktail-relay-lab-target \
    cargo build --release -p blaktail-coord -p blaktail-relay -p blaktaild -p blaktail-config \
 && mkdir -p /out \
 && cp target/release/blaktail-coord target/release/blaktail-relay \
       target/release/blaktaild target/release/blaktail-config /out/

FROM debian:bookworm-slim
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
