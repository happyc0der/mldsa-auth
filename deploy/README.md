# Deployment material

| File | What it is |
|---|---|
| `Caddyfile.example` | The reverse-proxy configuration the daemon is designed to sit behind. It is not illustrative: `tests/caddy_proxy.sh` validates this exact file, starts a real Caddy with it, logs in through it, and then removes `proxy_protocol` to prove the refusal. |

The systemd unit, the hardening flags and the operational runbook are V4-11.
