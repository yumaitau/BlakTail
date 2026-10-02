FROM amazonlinux:2023 AS build

ARG TARGETARCH
RUN case "$TARGETARCH" in arm64|amd64) ;; *) exit 2 ;; esac \
 && dnf install -y ca-certificates gcc gcc-c++ gzip make tar \
 && dnf clean all \
 && curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
      https://sh.rustup.rs -o /tmp/rustup-init.sh \
 && sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain 1.98.0 \
 && rm -f /tmp/rustup-init.sh

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

FROM debian:12-slim AS package

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
