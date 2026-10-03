# Fake TLS

**English** · [Русский](FAKE_TLS.ru.md)

Fake TLS is for when you run `tg-proxy` as a public or shared MTProto proxy on a server. The client's very first bytes look like a TLS 1.3 handshake to an ordinary website; only someone who knows the secret can tell the difference.

```bash
tg-proxy --host 0.0.0.0 --mtproto-port 443 --port 0 \
         --fake-tls-domain example.com --secret 00112233445566778899aabbccddeeff
```

The proxy prints an `ee` link:

```
tg://proxy?server=YOUR.SERVER.IP&port=443&secret=ee<secret><hex of "example.com">
```

## How it hides

1. The client sends a ClientHello whose random field is an HMAC keyed with your secret (plus a timestamp). `tg-proxy` verifies it and answers with a believable TLS 1.3 server flight, also authenticated with the secret.
2. **Anything that does not verify is relayed to the real `example.com`** — byte for byte, including the prober's own ClientHello. A scanner, or a censor's active probe, simply talks to the genuine website.
3. A **replayed** copy of a genuine ClientHello is treated like a probe, so recording a client's handshake and replaying it does not reveal the proxy. (Hellos are also only accepted within ±120 s of the server's clock.)
4. Non‑TLS traffic on the port gets the redirect a plain web server would send. A handshake that passes the TLS check but carries a wrong obfuscation secret is ignored silently.

## Choosing the domain

Pick a real, popular HTTPS site that **your server can reach** and that is not blocked for your users. It does not have to be yours and does not have to resolve to your server: it is only the name the connection pretends to be for, and the destination probes are forwarded to. Keep the clock of your server accurate (NTP).

## Behind nginx (share port 443 with a real site)

If the server also hosts a website on 443, let nginx route by SNI and hand the proxy's traffic to `tg-proxy` with the PROXY protocol so client addresses survive:

```nginx
stream {
    upstream mtproto { server 127.0.0.1:8446; }
    upstream website { server 127.0.0.1:8443; }   # your real HTTPS site

    map $ssl_preread_server_name $backend {
        example.com  mtproto;      # the --fake-tls-domain
        default      website;
    }

    server {
        listen 443;
        ssl_preread on;
        proxy_pass $backend;
        proxy_protocol on;         # tg-proxy needs --proxy-protocol; your website must accept it too
    }
}
```

```bash
tg-proxy --host 127.0.0.1 --mtproto-port 8446 --port 0 \
         --fake-tls-domain example.com --proxy-protocol --secret <32 hex chars>
```

The link then points at port **443** with `server=` set to your domain or IP.

## Notes

- Without `--fake-tls-domain` the proxy speaks plain obfuscated MTProto (`dd` link): fine for yourself or a trusted LAN, easier to recognise on the open Internet.
- Never put the secret in a world‑readable place or a public log. `tg-proxy` prints links to the console only and keeps the generated secret in a file readable by you alone.
