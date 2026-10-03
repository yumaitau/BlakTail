# BlakTail console (Next.js + Better Auth + Drizzle). Migrations are an explicit gate.
FROM rust:1.98-slim-bookworm AS config-build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY config ./config
COPY blaktail-config ./blaktail-config
COPY blaktail-coord ./blaktail-coord
COPY blaktail-relay ./blaktail-relay
COPY blaktail-relay-proto ./blaktail-relay-proto
COPY blaktaild ./blaktaild
COPY blaktail-ios-wg ./blaktail-ios-wg
RUN cargo build --release -p blaktail-config

FROM oven/bun:1.4.0-slim AS deps
WORKDIR /app
COPY package.json bun.lock ./
COPY apps/console/package.json ./apps/console/package.json
RUN bun ci

FROM oven/bun:1.4.0-slim AS prod-deps
WORKDIR /app
COPY package.json bun.lock ./
COPY apps/console/package.json ./apps/console/package.json
RUN bun ci --production

FROM oven/bun:1.4.0-slim AS build
WORKDIR /app/apps/console
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app /app
COPY apps/console /app/apps/console
# Build-time placeholders exist only for static compilation; real values are
# injected at runtime and must not persist in image metadata.
RUN DATABASE_URL=postgres://placeholder:placeholder@127.0.0.1:5432/placeholder \
    BETTER_AUTH_SECRET=build-time-placeholder-secret-32-chars-min \
    BETTER_AUTH_URL=http://localhost:3000 \
    COORD_BASE_URL=https://coord.example.internal \
    BLAKTAIL_AUTH_HMAC_SECRET=build-time-placeholder-secret-32-chars-min \
    bun run build

FROM build AS test
RUN bun run lint \
    && bun run typecheck \
    && bun run test

FROM oven/bun:1.4.0-slim
WORKDIR /app/apps/console
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOME=/tmp
RUN groupadd --system blaktail \
    && useradd --system --gid blaktail --home-dir /nonexistent --shell /usr/sbin/nologin blaktail
COPY --chown=blaktail:blaktail --from=prod-deps /app /app
COPY --chown=blaktail:blaktail --from=build /app/apps/console/.next ./.next
COPY --chown=blaktail:blaktail --from=build /app/apps/console/public ./public
COPY --chown=blaktail:blaktail --from=build /app/apps/console/scripts ./scripts
COPY --chown=blaktail:blaktail apps/console/package.json apps/console/drizzle.config.ts ./
COPY --chown=blaktail:blaktail apps/console/drizzle ./drizzle
COPY --from=config-build /src/target/release/blaktail-config /usr/local/bin/blaktail-config
COPY --chown=blaktail:blaktail --chmod=0755 deploy/docker/console-entrypoint.sh /usr/local/bin/console-entrypoint
USER blaktail
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD bun -e 'const r = await fetch("http://127.0.0.1:3000/sign-in"); if (!r.ok) process.exit(1)'
ENTRYPOINT ["console-entrypoint"]
CMD ["bun", "run", "start"]
