# amazonlinux:2023 (index digest; refresh: docker buildx imagetools inspect amazonlinux:2023)
FROM amazonlinux@sha256:3ccfbe800f864982b0a4e124a614b2382518cbd04b3c1cd35202bd46f392675b AS build

ARG TARGETARCH
# Pinned rustup-init binary, verified by sha256 before it runs. Refresh from
# https://static.rust-lang.org/rustup/archive/<ver>/<triple>/rustup-init.sha256
ARG RUSTUP_VERSION=1.29.3
ARG RUSTUP_SHA256_AMD64=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55
ARG RUSTUP_SHA256_ARM64=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282
RUN case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu; sha="$RUSTUP_SHA256_AMD64" ;; \
      arm64) triple=aarch64-unknown-linux-gnu; sha="$RUSTUP_SHA256_ARM64" ;; \
      *) exit 2 ;; \
    esac \
 && dnf install -y ca-certificates gcc gcc-c++ gzip make tar \
 && dnf clean all \
 && curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${triple}/rustup-init" \
      -o /tmp/rustup-init \
 && echo "${sha}  /tmp/rustup-init" | sha256sum --check - \
 && chmod 0755 /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain 1.98.0 \
 && rm -f /tmp/rustup-init

ENV CARGO_HOME=/root/.cargo
ENV RUSTUP_HOME=/root/.rustup
ENV PATH=/root/.cargo/bin:$PATH
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
ENV CARGO_INCREMENTAL=0
ENV RUSTFLAGS="--remap-path-prefix=/src=. --remap-path-prefix=/root/.cargo=cargo"

WORKDIR /src
COPY . .
RUN cargo build --locked --release -p blaktaild -p blaktail-config \
 && target/release/blaktaild --version

# debian:12-slim (index digest; refresh: docker buildx imagetools inspect debian:12-slim)

FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS package

ARG TARGETARCH
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

RUN apt-get update \
 && apt-get install -y --no-install-recommends dpkg-dev rpm \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml ./
COPY scripts/package-agent.sh scripts/agent-checksums.sh ./scripts/
COPY packaging/systemd/blaktaild.service ./packaging/systemd/blaktaild.service
COPY docs/linux-agent.md ./docs/linux-agent.md
COPY --from=build /src/target/release/blaktaild ./blaktaild
COPY --from=build /src/target/release/blaktail-config ./blaktail-config
RUN case "$TARGETARCH" in \
      arm64) target=aarch64-unknown-linux-gnu ;; \
      amd64) target=x86_64-unknown-linux-gnu ;; \
      *) exit 2 ;; \
    esac \
 && mkdir /out \
 && BLAKTAIL_TARGET="$target" scripts/package-agent.sh \
      deb ./blaktaild /out \
 && BLAKTAIL_TARGET="$target" scripts/package-agent.sh \
      rpm ./blaktaild /out \
 && scripts/agent-checksums.sh /out \
 && cd /out \
 && sha256sum --check SHA256SUMS

FROM scratch AS export
COPY --from=package /out/ /
