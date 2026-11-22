# Hedge as a systemd service

For a VM or a bare-metal host. Hedge runs as its own user, reads
`/etc/hedge/hedge.toml` and keeps witness, signing key and control token in
`/var/lib/hedge`. TLS ends at a reverse proxy on the same host
(`deploy/proxy/nginx.conf` or Caddy).

## Install

```bash
# 1. The binary (built with `cargo build --release`, or copied out of the image)
sudo install -m 0755 target/release/hedge /usr/local/bin/hedge

# 2. The service user
sudo install -m 0644 deploy/systemd/hedge.sysusers /usr/lib/sysusers.d/hedge.conf
sudo systemd-sysusers

# 3. The config: readable by the service, writable by root only
sudo install -d -o root -g hedge -m 0750 /etc/hedge
sudo install -o root -g hedge -m 0640 deploy/systemd/hedge.toml /etc/hedge/hedge.toml
sudo HEDGE_CONFIG=/etc/hedge/hedge.toml hedge check

# 4. The unit
sudo install -m 0644 deploy/systemd/hedge.service /etc/systemd/system/hedge.service
sudo systemctl daemon-reload
sudo systemctl enable --now hedge

# 5. Does it answer?
sudo HEDGE_CONFIG=/etc/hedge/hedge.toml hedge ready
sudo -u hedge HEDGE_CONFIG=/etc/hedge/hedge.toml hedge status
```

The listen addresses in [`hedge.toml`](hedge.toml) are loopback, because the
reverse proxy runs next to Hedge: `127.0.0.1:18765` for agents,
`127.0.0.1:18766` for the control API.

Presidio (names, phone numbers) is a container. Run the `hedge-presidio`
image next to Hedge, bound to loopback, and set `[presidio] url` – the unit
is hardened and cannot start containers itself. `hedge deploy compose` is
the shorter way if the host runs Docker anyway.

## Day to day

| What | How |
|---|---|
| Logs | `journalctl -u hedge -f` (one JSON object per request with `log.format = "json"`) |
| Change the policy | edit `/etc/hedge/hedge.toml`; Hedge reloads it within two seconds. `systemctl reload hedge` forces it. |
| Settings that need a restart | listen addresses, `[witness]`, `[telemetry]`, `[control]`, `[log]`: `systemctl restart hedge` |
| Add a developer | `sudo HEDGE_CONFIG=/etc/hedge/hedge.toml hedge client add <name>` |
| Add an admin | `sudo HEDGE_CONFIG=/etc/hedge/hedge.toml hedge admin add <name>` |
| Watch | `sudo -u hedge HEDGE_CONFIG=/etc/hedge/hedge.toml hedge watch` – or from an admin's own machine with `HEDGE_URL` and `HEDGE_CONTROL_TOKEN` |
| Upgrade | replace `/usr/local/bin/hedge`, `systemctl restart hedge`. Running answers get `shutdown_grace_secs` to finish. |

`hedge` on the command line reads `~/.hedge/hedge.toml` unless told
otherwise, so on this host always pass `HEDGE_CONFIG=/etc/hedge/hedge.toml`
(or put it into the admins' shell profile).

Everything else – witness rotation, backups, alerts, what to do when
something fails – is in [docs/operations.md](../../docs/operations.md).
