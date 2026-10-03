# syntax=docker/dockerfile:1

# ── Build a fully static binary (musl) ────────────────────────────────────────
FROM rust:1-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/tg-proxy /tg-proxy

# ── Minimal runtime: just the binary (Mozilla's CA roots are compiled in) ─────
FROM scratch
COPY --from=build /tg-proxy /tg-proxy
USER 65532:65532
EXPOSE 1443
# Listen on all interfaces, MTProto only (no unauthenticated SOCKS5 listener).
# These are environment defaults rather than CMD arguments on purpose: options
# you add after the image name must not silently discard them. Fix the secret
# with TG_PROXY_SECRET, otherwise a new one is generated on every start.
ENV TG_PROXY_HOST=0.0.0.0 TG_PROXY_PORT=0
ENTRYPOINT ["/tg-proxy"]
