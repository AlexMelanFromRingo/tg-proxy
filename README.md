# tg-proxy

High-performance Telegram WebSocket bridge proxy written in Rust.

A local SOCKS5 proxy that tunnels Telegram Desktop / Mobile traffic over **WebSocket (WSS, port 443)** to Telegram's relay servers (`kws*.web.telegram.org`). Useful in regions where Telegram's raw IP ranges are blocked by DPI, but HTTPS/WebSocket traffic is allowed.

```
Telegram Desktop / Mobile
        │  SOCKS5
        ▼
 127.0.0.1:1080  (tg-proxy)
        │  WSS (TLS WebSocket, port 443)
        ▼
 kws{N}.web.telegram.org  ──►  Telegram DC
```

## How it works

1. Runs a local SOCKS5 proxy on `127.0.0.1:1080`
2. Intercepts connections to Telegram IP ranges
3. Reads the 64-byte MTProto obfuscation init packet and extracts the DC ID
4. Establishes a TLS WebSocket connection to the appropriate DC relay (`kws{DC}.web.telegram.org`)
5. Bridges data bidirectionally — each MTProto message becomes one WebSocket frame
6. Falls back to direct TCP if WebSocket is unavailable (e.g. 302 redirect)

## Download

Pre-built static binaries are available on the [Releases](../../releases) page:

| Platform | File |
|---|---|
| Linux x86_64 (static) | `tg-proxy-linux-x86_64` |
| Linux aarch64 (static, Raspberry Pi etc.) | `tg-proxy-linux-aarch64` |
| Windows x86_64 | `tg-proxy-windows-x86_64.exe` |
| macOS Intel | `tg-proxy-macos-x86_64` |
| macOS Apple Silicon | `tg-proxy-macos-aarch64` |

## Quick start

```bash
# Linux / macOS
chmod +x tg-proxy-linux-x86_64
./tg-proxy-linux-x86_64
```

```cmd
# Windows
tg-proxy-windows-x86_64.exe
```

Then configure Telegram Desktop:
**Settings → Advanced → Connection type → Proxy → Add proxy → SOCKS5**
- Server: `127.0.0.1`
- Port: `1080`
- Username / Password: leave empty

Or click this link to open Telegram and apply settings automatically:
```
tg://socks?server=127.0.0.1&port=1080
```

## Mobile (Telegram on phone, same LAN)

Run with `--host 0.0.0.0` to listen on all interfaces:

```bash
./tg-proxy-linux-x86_64 --host 0.0.0.0
```

Then in Telegram Mobile → Settings → Data and Storage → Proxy → Add Proxy → SOCKS5:
- Server: your computer's LAN IP (e.g. `192.168.1.5`)
- Port: `1080`

Or tap the deeplink (replace `192.168.1.5` with your actual LAN IP):
```
tg://socks?server=192.168.1.5&port=1080
```

## CLI options

```
Usage: tg-proxy [OPTIONS]

Options:
  --host <HOST>              Listen host [default: 127.0.0.1]
  -p, --port <PORT>          Listen port [default: 1080]
  --dc-ip <DC:IP>            Target IP for a DC (repeatable)
                             [default: 2:149.154.167.220, 4:149.154.167.220]
  -v, --verbose              Enable debug logging
  --skip-tls-verify          Disable TLS certificate verification (insecure)
  --pool-size <N>            Pre-warmed WS connections per DC [default: 4]
  --pool-max-age <SECS>      Max age of a pooled connection [default: 120]
  --connect-timeout <SECS>   Connection timeout [default: 10]
  -h, --help                 Print help
```

### Example: custom DCs

```bash
./tg-proxy --dc-ip 1:149.154.175.50 --dc-ip 2:149.154.167.220 --dc-ip 4:149.154.167.220 -v
```

## Build from source

Requires Rust 1.75+.

```bash
git clone https://github.com/AlexMelanFromRingo/tg-proxy
cd tg-proxy
cargo build --release
./target/release/tg-proxy
```

## Improvements over the original Python proxy

| | Python original | This (Rust) |
|---|---|---|
| TLS verification | ❌ Disabled (`ssl.CERT_NONE`) | ✅ Full (WebPKI + system roots) |
| MTProto DC patch | ⚠️ Sign inverted bug | ✅ Fixed |
| Message splitter | ⚠️ Drops data on chunk boundary | ✅ Buffered across boundaries |
| Concurrency | GIL-limited | True async, no GIL |
| Binary size | ~10 MB PyInstaller bundle | ~4 MB static binary |
| Platforms | Windows only (tray app) | Linux / Windows / macOS |

## Security

- Only connects to **official Telegram servers**: `kws{1-5}.web.telegram.org` and `kws{1-5}-1.web.telegram.org`
- No third-party services involved
- TLS certificate verification enabled by default
- Source code is fully auditable — no obfuscation, no bundled runtimes
- CI builds binaries directly from source via GitHub Actions

## License

MIT
