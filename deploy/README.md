# Deploying Hedge

| Directory | What |
|---|---|
| [`central/`](central/README.md) | one host: the templates of `hedge deploy compose` – Hedge and Presidio, Caddy (TLS) and Grafana as profiles. Do not start it from here; the command fills in the version and writes the directory. |
| [`systemd/`](systemd/README.md) | a VM: hardened unit, service user, install steps |
| [`helm/hedge/`](helm/hedge/values.yaml) | Kubernetes: one replica, `Recreate`, volume, two Services, optional ingresses |
| [`proxy/`](proxy/nginx.conf) | nginx in front of Hedge, for hosts that already run it |
| [`clients/claude-code/`](clients/claude-code/README.md) | pointing Claude Code at a central Hedge, for one developer or the whole organisation |
| [`docker/`](docker/entrypoint.sh) | what the image is made of: entrypoint and the config baked in |
| [`presidio/`](presidio/Dockerfile) | the `hedge-presidio` image: Presidio with German and English models and Hedge's own small server |
| [`compose/`](compose/docker-compose.yml) | Grafana stack to try telemetry locally; its dashboard and alert rules are reused by `central/` |

The image comes from the [`Dockerfile`](../Dockerfile) at the root. The
runbook for whoever operates it: [`docs/operations.md`](../docs/operations.md).
