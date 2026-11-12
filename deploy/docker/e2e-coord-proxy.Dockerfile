# ARM64/multi-arch coordinator HTTP bridge and ephemeral certificate generator.
# caddy:2.10.2-alpine (index digest; refresh: docker buildx imagetools inspect caddy:2.10.2-alpine)
FROM caddy@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d

RUN apk add --no-cache openssl
COPY deploy/docker/e2e-coord-proxy.Caddyfile /etc/caddy/Caddyfile

EXPOSE 8080
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
