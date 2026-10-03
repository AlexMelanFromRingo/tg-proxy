# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] — 2026-10-03

A rewrite of the routing core and the full feature set of the original
[`tg-ws-proxy`](https://github.com/Flowseal/tg-ws-proxy), plus tooling to find out
what works on a given network.

### Added
- **MTProto-proxy mode** (`--mtproto-port`, default 1443) with a persistent secret
  and `tg://proxy` links; SOCKS5 stays available (`--port`).
- **Fake TLS** (`--fake-tls-domain`): HMAC-verified ClientHello, authenticated
  ServerHello, probe masking to the real site, replay protection, HTTP redirect for
  non-TLS traffic, PROXY protocol v1 (`--proxy-protocol`).
- **Routes beyond the direct WebSocket**: SNI fronting, Cloudflare Worker
  (`--cfproxy-worker-domain`), Cloudflare-proxied domains (`--cfproxy-domain`, with a
  community pool refreshed hourly), raw TCP — with remembered failures and cool-downs.
- `cloudflare/worker.js`, a Worker that only relays to Telegram's address ranges.
- **`--check`**: a real `req_pq` → `resPQ` handshake with Telegram over every route,
  reported per datacenter.
- **`--upstream-socks5`**: send all outbound connections through an existing tunnel
  (SOCKS5 with optional authentication, remote DNS).
- DC203, Telegram test datacenters (`--force-test-dc`), `--no-direct`, `--no-cfproxy`,
  `--no-secure`, `--buf-kb`, log file with rotation, domain masking in logs.
- Environment variables for the key options (`TG_PROXY_*`), Dockerfile, systemd example.
- Bilingual documentation (English / Русский), end-to-end test suite.

### Changed
- WebSocket frames are parsed from a buffer: reads are cancel-safe, pings are answered
  immediately (previously only before the next client read), interleaved control frames
  no longer drop a fragmented message.
- MTProto packet splitting understands abridged, intermediate and padded-intermediate
  transports and is applied to every WebSocket connection (it was limited to patched
  inits and to the abridged transport).
- The connection pool health-checks idle connections, uses each connection as soon as
  it is ready, and backs off exponentially instead of hammering a blocked address.
- Default direct-connect timeout 10 s → 5 s.
- Minimum supported Rust version is now 1.85 (that is what the dependencies require).
- Fronted connections verify the certificate against `web.telegram.org`
  (the original accepts any publicly valid certificate).

### Security
- The SOCKS5 passthrough refuses loopback, private and link-local destinations (it used to
  relay to anything, which made a shared SOCKS5 port a way into the proxy host's network).
- The Cloudflare-domain list downloader can no longer be crashed by a hostile chunked
  response (integer overflow on the chunk size).
- Fake-TLS masking honours `--upstream-socks5`, so probes see the same behaviour either way.

### Fixed
- A failing Worker or Cloudflare domain is skipped for 30 s instead of being retried on every
  client connection; the Worker pool refills after a miss (it only refilled after a hit) and backs
  off after a failed refill.
- A short probe timeout during a DC's cool-down no longer escalates into an hour-long block of
  the whole gateway IP.
- The Fake-TLS redirect for non-TLS traffic is no longer destroyed by a connection reset on
  BSD/macOS (the reply is finished and the request drained before closing), so probes get what a
  real web server would send.
- TCP keepalive on all sockets, so a vanished client (phone left the Wi-Fi) is reaped.
- Wrong DC gateway list: only `149.154.167.220` serves the WebSocket gateway, and only
  for DC2 and DC4; other datacenters are now reached through the other routes instead
  of silently falling back to a blocked TCP address.

### Removed
- Nothing from the command line. The original project's Windows/macOS tray GUI,
  autostart and update checker are not part of this command-line tool.

## [1.0.1], [1.0.0]

Earlier releases of the SOCKS5 WebSocket bridge; see the
[GitHub releases](https://github.com/AlexMelanFromRingo/tg-proxy/releases).
