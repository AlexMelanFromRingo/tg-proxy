# Cloudflare Worker

**English** · [Русский](CLOUDFLARE.ru.md)

A Worker is a tiny program that runs on Cloudflare's network. `tg-proxy` talks to it over HTTPS/WebSocket; the Worker opens the TCP connection to Telegram from *Cloudflare's* side. To a censor you are simply talking to Cloudflare.

Why bother:

- it is the one route that reaches **every** Telegram datacenter (DC1–DC5, DC203); Telegram's own WebSocket gateway serves only DC2 and DC4;
- it is **yours** — no third‑party pool involved;
- it is **free** and needs no domain name;
- one Worker can serve you and all your friends.

The Worker in [`cloudflare/worker.js`](../cloudflare/worker.js) is not an open relay: it refuses every destination that is not inside Telegram's published address ranges.

## Set it up (about 5 minutes)

1. Create a free account at <https://dash.cloudflare.com> and confirm your e‑mail.
2. Open **Compute (Workers) → Workers & Pages → Create → Start with Hello World → Deploy**.
3. Click **Edit code**, delete everything, paste the contents of [`cloudflare/worker.js`](../cloudflare/worker.js), click **Deploy**.
4. Copy the Worker's address, something like `tg-relay.your-name.workers.dev`.
5. Start the proxy with it:

   ```bash
   tg-proxy --cfproxy-worker-domain tg-relay.your-name.workers.dev
   ```

6. Verify: `tg-proxy --check --cfproxy-worker-domain tg-relay.your-name.workers.dev` should show ✔ for every datacenter under *Cloudflare Worker*.

> **The dashboard does not open from my network.** Some networks throttle `cloudflare.com` / `workers.dev`. You only need the dashboard once, to deploy: do the setup from a network where it works, or through any VPN. Afterwards the Worker keeps running without you.

<details>
<summary>Prefer the command line? (wrangler)</summary>

```bash
npx wrangler login
npx wrangler deploy cloudflare/worker.js --name tg-relay --compatibility-date 2025-01-01
```

The address is printed at the end.
</details>

## Using it

```bash
# one Worker
tg-proxy --cfproxy-worker-domain tg-relay.your-name.workers.dev

# several, to spread the load (repeat the flag or use commas)
tg-proxy --cfproxy-worker-domain a.workers.dev,b.workers.dev

# or an environment variable
TG_PROXY_WORKER_DOMAINS=tg-relay.your-name.workers.dev tg-proxy
```

The Worker is tried right after the direct route and before the community domain pool. Share only its **address** with friends — they put it into the same option.

## Limits and privacy

- The free plan has a daily request limit (Cloudflare documents 100,000 per account at the time of writing; check their current limits). A personal proxy opens a modest number of connections, so you are unlikely to approach it. If a Worker is exhausted, requests to it fail and `tg-proxy` moves on to the next route.
- Cloudflare can see *that* you connect and how much — not what you say. Your messages stay MTProto‑encrypted between the Telegram app and Telegram's servers.
- `--no-secure` makes `tg-proxy` talk to the Worker over plain HTTP on port 80. It can speed up connection setup when TLS to Cloudflare is what gets disrupted, but it exposes the Worker's address and the request path to everyone on the way. Use it only if nothing else works.

## Your own domain instead (Cloudflare‑proxied domains)

If you own a domain, you can put it on Cloudflare and use route 3 with it instead of the community pool.

1. Add the domain to Cloudflare (<https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/>).
2. **SSL/TLS → Overview**: set the mode to **Flexible**.
3. **DNS → Records**: add these **proxied** (orange cloud) `A` records:

   | Name | IPv4 |
   |---|---|
   | `kws1` | `149.154.175.50` |
   | `kws2` | `149.154.167.51` |
   | `kws3` | `149.154.175.100` |
   | `kws4` | `149.154.167.91` |
   | `kws5` | `149.154.171.5` |
   | `kws203` | `91.105.192.100` |

4. Run `tg-proxy --cfproxy-domain your-domain.com` and confirm with `--check`.

This is the setup used by the original `tg-ws-proxy` project; it was not possible to verify it end to end here, so rely on `--check`. Cloudflare limits concurrent WebSocket connections on free domains, so a Worker is usually the more dependable choice.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `--check` shows `HTTP 403` for the Worker | The destination was outside Telegram's ranges. Make sure you deployed the unmodified `worker.js`. |
| `HTTP 404` | Wrong path or you opened the address in a browser; `tg-proxy` uses `/apiws`. |
| `timeout` for every Worker probe | Cloudflare is unreachable from this network, or the address is mistyped. Try `--upstream-socks5`, or `--no-secure` as a last resort. |
| `HTTP 429` / error 1015 | The Worker or domain hit a Cloudflare limit. Add a second Worker. |
