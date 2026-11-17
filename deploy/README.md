# Deployment material

| File | What it is |
|---|---|
| `Caddyfile.example` | The reverse-proxy configuration the daemon is designed to sit behind. It is not illustrative: `tests/caddy_proxy.sh` validates this exact file, starts a real Caddy with it, logs in through it, and then removes `proxy_protocol` to prove the refusal. |
| `authd.conf.example` | The daemon's configuration with every key, its default and what it is for. |
| `mldsa-authd.service` | The systemd unit: the sandboxing spec §16 requires, checked value by value by `tests/unit_directives.sh`. |
| `mldsa-authd-audit.service`, `mldsa-authd-audit.timer` | The hourly verification of the audit chain. |
| `RUNBOOK.md` | Installing, operating, backing up, restoring and upgrading, step by step. CI runs every command block of it on two fresh Ubuntu hosts (`tools/rehearse_runbook.py`). |
| `fetch-deps.sh` | Fills an offline dependency cache, verified against the same pins the build enforces, for a host that builds without a network. |
