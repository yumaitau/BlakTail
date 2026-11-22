# Throwaway coordinator certificates for compose quickstarts.
# debian:bookworm-slim (index digest; refresh: docker buildx imagetools inspect debian:bookworm-slim)
FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash openssl \
 && rm -rf /var/lib/apt/lists/*
COPY scripts/dev-certs.sh /usr/local/bin/dev-certs
COPY deploy/docker/certs-entrypoint.sh /usr/local/bin/certs-entrypoint
RUN chmod 0755 /usr/local/bin/dev-certs /usr/local/bin/certs-entrypoint
VOLUME ["/certs"]
ENTRYPOINT ["/usr/local/bin/certs-entrypoint"]
