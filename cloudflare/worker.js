// tg-proxy · Cloudflare Worker
//
// A tiny WebSocket → raw-TCP relay. tg-proxy connects to
//   wss://<your-worker>/apiws?dst=<telegram-dc-ip>&dc=<n>
// and this Worker opens a TCP socket to dst:443 from Cloudflare's network and
// pipes the bytes both ways. From the censor's point of view you are only talking
// to Cloudflare; the Telegram traffic itself stays MTProto-encrypted end to end.
//
// Unlike a generic relay, this one refuses every destination that is not inside
// Telegram's published address ranges, so it cannot be abused as an open proxy
// on your account.
//
// Deploy: https://dash.cloudflare.com → Workers & Pages → Create → Hello World →
// Edit code → paste this file → Deploy. See docs/CLOUDFLARE.md.

import { connect } from "cloudflare:sockets";

// https://core.telegram.org/resources/cidr.txt (IPv4)
const TELEGRAM_CIDRS = [
  "91.105.192.0/23",
  "91.108.4.0/22",
  "91.108.8.0/22",
  "91.108.12.0/22",
  "91.108.16.0/22",
  "91.108.20.0/22",
  "91.108.56.0/22",
  "95.161.64.0/20",
  "149.154.160.0/20",
  "185.76.151.0/24",
];

function ipv4ToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((n) => n > 255)) return null;
  return o[0] * 16777216 + o[1] * 65536 + o[2] * 256 + o[3];
}

const RANGES = TELEGRAM_CIDRS.map((cidr) => {
  const [ip, bits] = cidr.split("/");
  const base = ipv4ToInt(ip);
  return [base, base + 2 ** (32 - Number(bits)) - 1];
});

export function isTelegramIp(ip) {
  const n = ipv4ToInt(ip);
  return n !== null && RANGES.some(([lo, hi]) => n >= lo && n <= hi);
}

function toBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (typeof data === "string") return new TextEncoder().encode(data);
  return null;
}

export default {
  async fetch(request) {
    if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
      return new Response("Expected a WebSocket upgrade", { status: 426 });
    }
    const url = new URL(request.url);
    if (url.pathname !== "/apiws") {
      return new Response("Not found", { status: 404 });
    }
    const dst = url.searchParams.get("dst") || "";
    if (!isTelegramIp(dst)) {
      return new Response("Destination is not a Telegram datacenter", { status: 403 });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    const socket = connect({ hostname: dst, port: 443 });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    const shutdown = () => {
      try { writer.close(); } catch {}
      try { socket.close(); } catch {}
    };

    // WebSocket → TCP. Chained so message order is preserved and the socket's
    // backpressure is honoured.
    let chain = Promise.resolve();
    server.addEventListener("message", (event) => {
      const bytes = toBytes(event.data);
      if (!bytes) return;
      chain = chain
        .then(() => writer.write(bytes))
        .catch(() => {
          try { server.close(1011, "tcp write failed"); } catch {}
        });
    });
    server.addEventListener("close", shutdown);
    server.addEventListener("error", shutdown);

    // TCP → WebSocket.
    (async () => {
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value && value.byteLength) server.send(value);
        }
      } catch {
        // connection reset by the datacenter
      } finally {
        try { server.close(1000, "tcp closed"); } catch {}
        try { reader.releaseLock(); } catch {}
        try { socket.close(); } catch {}
      }
    })();

    return new Response(null, { status: 101, webSocket: client });
  },
};
