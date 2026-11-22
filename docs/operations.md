# Operating Hedge as a central gateway

One Hedge for a team: developers point their agents at it, admins watch and
approve from their own machines. This is the runbook for the person who runs
it.

- [What you are running](#what-you-are-running)
- [Three ways to deploy](#three-ways-to-deploy)
- [First steps on a central gateway](#first-steps-on-a-central-gateway)
- [The reverse proxy in front](#the-reverse-proxy-in-front)
- [Developers: clients](#developers-clients)
- [Admins](#admins)
- [Day to day](#day-to-day)
- [The witness](#the-witness)
- [Monitoring](#monitoring)
- [When something fails](#when-something-fails)
- [Upgrade and rollback](#upgrade-and-rollback)
- [Corporate proxy and CA](#corporate-proxy-and-ca)
- [Who can do what](#who-can-do-what)
- [What has been verified, and what has not](#what-has-been-verified-and-what-has-not)

## What you are running

**Hedge is a single-instance service.** Token budgets, pending approvals and
the memory of findings already seen live in the process. The witness chain
has exactly one writer. Two processes on the same witness would both continue
the chain with the same sequence number, and it would no longer verify. So:

- one instance per chain – never two replicas, never a rolling update that
  overlaps the old and the new process;
- to scale or to separate teams, run one Hedge per team, each with its own
  volume, key and chain.

```
agent ──HTTPS──▶ reverse proxy ──HTTP──▶ hedge :18765 ──HTTPS──▶ api.anthropic.com
                 (TLS, no buffering)      │    :18766 control API (admins only)
                                          ├──▶ /var/lib/hedge   witness, signing key, control token
                                          └──▶ OTLP collector   traces, metrics (optional)
```

| Port | What | Who |
|---|---|---|
| `server.listen` (18765) | the proxy: `/<upstream>/…`, plus `/health` and `/ready` | agents, through the reverse proxy |
| `control.listen` (18766) | the control API: `/_hedge/status`, `/_hedge/approvals`, `/_hedge/witness`, plus `/health` and `/ready` | admins only |

With `control.listen` set, `/_hedge/*` does not exist on the proxy port.
Without it, both share `server.listen` and the reverse proxy has to keep
`/_hedge/*` away from developers.

| File | What | Secret |
|---|---|---|
| `/etc/hedge/hedge.toml` | policy, clients and admins (hashes only), webhook URL | writable by root only – see [Who can do what](#who-can-do-what) |
| `/var/lib/hedge/witness.key` | Ed25519 signing key, mode 0600 | yes. Back it up. |
| `/var/lib/hedge/witness.key.pub` | public key | no – give it to whoever verifies the chain |
| `/var/lib/hedge/control.token` | the local control token, mode 0600 | yes |
| `/var/lib/hedge/witness.jsonl` | the active segment of the chain | no prompt text, but per-person activity – see [Privacy](#privacy) |
| `/var/lib/hedge/witness.<first>-<last>.jsonl` | closed segments, read-only | same |

## Three ways to deploy

| | For | Where |
|---|---|---|
| Compose | one host: Hedge and Presidio, Caddy (TLS) and Grafana as profiles | `hedge deploy compose --tls` writes the directory; its README has the steps ([template](../deploy/central/README.md), in German) |
| systemd + your reverse proxy | a VM that already runs nginx | [`deploy/systemd`](../deploy/systemd/README.md), [`deploy/proxy/nginx.conf`](../deploy/proxy/nginx.conf) |
| Helm | Kubernetes | [`deploy/helm/hedge`](../deploy/helm/hedge/values.yaml) |

All three use the same image or binary. The Compose directory and the chart
bring their own config; the commented starting point for a host is
[`deploy/systemd/hedge.toml`](../deploy/systemd/hedge.toml).

Build the image once and push it to your registry:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t registry.example.com/hedge:0.1.0 --push .
```

Presidio (names and phone numbers) is a second image, built from
[`deploy/presidio`](../deploy/presidio/Dockerfile); in the Compose directory
`docker compose build presidio` does it. The chart and the systemd unit run
Hedge without it – point `[presidio] url` at a Presidio you run next to it.

The image runs as uid 10001, reads `/etc/hedge/hedge.toml` and creates the
signing key and the control token on the volume at `/var/lib/hedge` on first
start (`hedge init --keys-only`). An existing key is never touched.

On Kubernetes the chart runs one replica with `strategy: Recreate`. Do not
change either.

## First steps on a central gateway

1. **Start in observe.** `mode = "observe"`, `tools.enforce = false`. Nothing
   is changed or blocked; everything is recorded.
2. **Check it.** `hedge ready` (exit code 0), `hedge status`, `hedge doctor`.
3. **Add the first developer:** `hedge client add alice`. Give them the two
   lines it prints. Then set `require_client = true`.
4. **Add yourself as an admin:** `hedge admin add anna`. From your own
   machine, `HEDGE_URL` and `HEDGE_CONTROL_TOKEN` are all the CLI needs.
5. **Point agents at it** – see [Developers: clients](#developers-clients).
6. **Read the report for a week:** `hedge report --since 7d`. Allowlist your
   own infrastructure (`[allow] domains`), adjust severities.
7. **Tighten:** `mode = "redact"`, then `tools.enforce = true`. For real
   separation of duties set `approve_in_chat = false`: a held tool call then
   waits until an admin decides.
8. **Turn telemetry on** and connect the alert rules to a contact point. The
   rule "no heartbeat" is the one that tells you Hedge is down.

## The reverse proxy in front

Hedge speaks plain HTTP. Whatever terminates TLS in front of it has to do six
things. They are marked (1)–(6) in
[`deploy/central/Caddyfile`](../deploy/central/Caddyfile) and
[`deploy/proxy/nginx.conf`](../deploy/proxy/nginx.conf); the Helm chart
carries them as ingress-nginx annotations.

1. **Never buffer answers.** They are server-sent events. With nginx's
   default buffering the whole answer arrives at once when it is finished,
   and the agent looks frozen until then.
2. **Allow long, quiet connections.** Hedge waits up to 600 s for the model
   (`timeouts.request_secs`), and a held tool call keeps the connection open
   until a human decides (`tools.approval_timeout_secs`).
3. **Allow large request bodies** – at least `server.max_body_mb` (10). nginx
   allows 1 MB unless told otherwise. Above its own limit Hedge answers 413
   with a reason; the entry is in the witness.
4. **No HTTP→HTTPS redirect for the API.** Hand out the `https://` address
   and do not listen on port 80 for this name. A redirect can lose the
   request body or the credential header.
5. **Keep `/_hedge/*` for admins** – by source network, in addition to the
   token. Hide `/health` and `/ready` from the outside.
6. **Pass headers through.** `anthropic-*`, `authorization`, `x-api-key`,
   `x-hedge-client-token`. No web application firewall on the request body
   of `/v1/messages`: prompts look like attacks to a WAF.

## Developers: clients

One token per developer or per machine. Hedge stores only its SHA-256.

```bash
hedge client add alice                                   # writes the config, prints the token once
hedge client add ci-runner --expires 2027-01-31 --daily-tokens 500000
hedge client list
hedge client rotate alice                                # new token, the old one stops working
hedge client remove alice
```

If the config comes from Git or a ConfigMap, add `--print`: the block is
printed and you paste it where the config is managed.

Every witness entry, metric and report line carries the client name. A
client's `daily_tokens` overrides `[budget] daily_tokens`; budgets reset at
00:00 UTC. A token is valid through its `expires` day (UTC).

### Claude Code

Two values per developer: the base URL with the upstream prefix, and the
token as an extra header.

```bash
export ANTHROPIC_BASE_URL=https://hedge.example.com/anthropic
export ANTHROPIC_CUSTOM_HEADERS="x-hedge-client-token: hc_…"
```

To roll the URL out to every machine and keep developers from changing it,
use Claude Code's managed settings –
[`deploy/clients/claude-code`](../deploy/clients/claude-code/README.md).

What a developer sees when Hedge says no:

| Status | Type | Why |
|---|---|---|
| 401 | `hedge_unknown_client` | token missing, unknown or expired (the message says which) |
| 403 | `hedge_blocked` | a high-severity finding in `block` mode |
| 403 | `hedge_model_not_allowed` | the model is not on the allowlist |
| 429 | `hedge_budget_exceeded` | daily or session budget used up |
| 413 | `hedge_request_too_large` | body above `server.max_body_mb` |
| 404 | `hedge_unknown_upstream` | the path prefix names no upstream |
| 502 | `hedge_upstream_error` | the LLM API is unreachable |

Hedge's own refusals (401, 403, 413, 429) carry `x-should-retry: false`, so
the Anthropic and OpenAI SDKs give up instead of retrying a decision that
will not change.

## Admins

```bash
hedge admin add anna        # prints the token once
hedge admin list
hedge admin rotate anna
hedge admin remove anna
```

On the admin's machine:

```bash
export HEDGE_URL=https://hedge.example.com
export HEDGE_CONTROL_TOKEN=ha_…

hedge status                # mode, counters, budgets, witness health
hedge approvals             # what is waiting
hedge approve <id>          # or: hedge deny <id>
hedge tail -f               # the witness, live
hedge sessions --since 24h
hedge report --since 7d
hedge watch                 # the terminal view, with approvals by key
hedge rotate                # close the active witness segment
```

Every approval by an admin is recorded with their name:
`1ea48f approved via control api (anna) · Bash · HEDGE-SHELL-003`. The local
control token on the Hedge host keeps working and stays nameless
(`via control api`) – use it for scripts on the host, not for people.

## Day to day

| What | How |
|---|---|
| Change the policy | edit `hedge.toml`. Hedge reloads it within two seconds (or on SIGHUP). A broken file is rejected, the previous config stays active, and both outcomes are in the witness – the successful reload with the SHA-256 of the file. |
| Settings that need a restart | `server.listen`, `[control]`, `[witness] path/key/enabled`, `[telemetry]`, `[log]` |
| Stop | SIGTERM. No new connections; running answers get `server.shutdown_grace_secs` (30) to finish. What is still running after that is recorded as cut off, then Hedge exits. Give the platform a slightly longer stop timeout. |
| Is it healthy? | `hedge ready` – exit code 0 or 1, for scripts and health checks |
| What did it do? | `hedge report`, `hedge sessions`, `hedge tail --alerts` |

After a restart, pending approvals are gone – the agent has to ask again –
and today's budgets are restored from the witness.

## The witness

### Segments

With `[witness] rotate_mb = 64` Hedge closes the active file at that size
and continues in a new one. `hedge rotate` does it by hand. The closed
segment is renamed to `witness.<first>-<last>.jsonl` and made read-only; the
new segment starts with an entry `rotate` that names it. The chain itself
does not break: sequence numbers and hashes run on across segments.

- `hedge verify` checks all segments in the directory as one chain.
- `hedge verify --witness <segment>` checks one segment on its own.
- Readers (`tail`, `sessions`, `report`, `watch`, `export`) see closed
  segments as long as they lie next to the active file.
- At start Hedge reads only the active segment. Without rotation, start time
  and memory grow with the file.

Archive closed segments wherever you keep evidence (object storage with a
retention lock, a backup). You may move them away; Hedge does not need them
to continue, only to answer questions about the past.

Never rotate with `logrotate`. Hedge holds the file open and would keep
writing into the moved file.

### Anchors

Cutting off the newest entries cannot be seen from the files alone. Keep the
head somewhere else and check against it:

```bash
hedge head                                   # 12049:4d0f…  → store it outside this host
hedge verify --anchor 12049:4d0f…
```

A daily cron line that appends `hedge head` to a file in another system is
enough. With telemetry on, every span carries the sequence number and hash
of its entry, so the tracing backend is a second anchor.

### Backup

Back up `/var/lib/hedge`: the signing key (once – it never changes), the
closed segments (they never change either) and the active segment. The chain
is verified against exactly one key; a new key means a new chain. If the key
is lost, the old chain can still be verified with `witness.key.pub`, but not
continued.

### After a crash or a full disk

- **A write fails** (disk full): the request still goes through – that is a
  decision, not an accident – and Hedge says so loudly: an error in the log,
  the metric `hedge_witness_errors`, the alert "witness write failed",
  `/ready` answers 503, `hedge status` shows the error. A half-written line
  is removed at once, so the file stays readable. When space is back the
  next entry follows the last complete one.
- **Hedge finds a torn last line at start** (crash in the middle of a
  write): the fragment is saved next to the witness as
  `witness.jsonl.torn-<time>`, removed from the file, and the repair is
  recorded as an entry `recovered` with the fragment's size and SHA-256.
- **An unreadable line in the middle** is not repaired. Hedge refuses to
  start and names the line. That is damage or tampering; restore from backup
  or start a new chain.

If you want no traffic without a record, let the platform act on `/ready`
instead of `/health` (Helm: `readiness.requireWitness = true`).

### Privacy

The witness holds no prompt text and no credentials. It does hold who
(client), when, which model, how many tokens, a 120-character preview of
each tool call and a masked hint for each finding. Collected centrally, that
is a record of individual people's work. In a company with a works council
this usually needs their agreement, and it needs a purpose, a retention
period and an access rule. `[witness] tool_preview = false` and
`hints = false` remove the two human-readable parts. This is an assessment,
not legal advice.

## Monitoring

| Signal | Meaning |
|---|---|
| `GET /health` | the process answers. Always 200. |
| `GET /ready` | 200 `{"ready":true}`; 503 `{"ready":false,"waiting_for":[…]}` with `witness is failing`, `shutting down` or `presidio (starting|unavailable)` – the last only once Presidio findings are enforced and `on_unavailable = "block"` |
| `hedge ready` | asks `/ready`, exit code 0 or 1 |
| metric `hedge_up` | 1 with every export. Missing = Hedge is down or cut off from the collector. |
| metric `hedge_witness_errors` | failed writes to the chain |
| `hedge status` | counters, budgets per client, witness health and segments |

Metrics are pushed over OTLP/HTTP every 15 s (`[telemetry] endpoint`); there
is no `/metrics` endpoint to scrape. `hedge_requests`, `hedge_findings`,
`hedge_tool_calls`, `hedge_tokens`, `hedge_request_duration_ms`,
`hedge_witness_errors`, `hedge_up`, and for Presidio `hedge_presidio_up`,
`hedge_presidio_texts`, `hedge_presidio_duration_ms`,
`hedge_presidio_unscanned`. Labels include `client`, `model`, `upstream`,
`action`, `kind`, `rule` – never a session.

The alert rules in `deploy/compose/grafana/alerting/hedge-alerts.yaml`:

| Rule | Fires when |
|---|---|
| high-severity finding in a prompt | a secret was sent towards an LLM API |
| tool call denied, rejected or timed out | the policy stopped a call |
| witness write failed | requests are passing without a record |
| no heartbeat | `hedge_up` has been missing for two minutes |
| Presidio is not ready | Presidio does not answer or lacks a configured language |
| requests passed without the Presidio check | requests reached an LLM API without a complete check for names |

Connect them to a contact point (Slack, e-mail) in Grafana; without one they
only show in the UI.

Logs: `[log] format = "json"` writes one JSON object per request to stdout.
Timestamps are UTC.

## When something fails

| What you see | What it means | What to do |
|---|---|---|
| alert "no heartbeat" | Hedge is down, or cannot reach the collector | `systemctl status hedge` / `docker compose ps` / `kubectl get pods`; `hedge ready` |
| alert "witness write failed", `/ready` 503 | the volume is full or read-only | free space or grow the volume; rotate and move closed segments away. Requests in the meantime were not recorded. |
| Hedge does not start: `witness file … line N` | an unreadable line in the middle of the witness | restore the file from backup, or move it away and start a new chain |
| Hedge does not start: `cannot set up the HTTPS client` | no CA certificates | install `ca-certificates`; check `SSL_CERT_FILE` |
| agents hang, then get everything at once | the reverse proxy buffers | point (1) above |
| agents get 413 with HTML | the reverse proxy's body limit | point (3) above |
| agents get 401 `hedge_unknown_client` | no token, wrong token or expired | `hedge client list`; the message names an expired client |
| agents get 429 | budget used up | `hedge status` shows usage and limit per client |
| agents get 503 `hedge_presidio_unavailable`, `/ready` 503 `presidio (…)` | Presidio is away and the policy is not to send what it could not check | `hedge presidio status` names the reason; `docker compose logs presidio`. The witness has `presidio_unavailable` and, once it is back, `presidio_ready`. |
| agents get 502 | the LLM API is unreachable from Hedge | `hedge doctor`; proxy and CA settings below |
| a held call is never answered | nobody saw it | `tools.notify_webhook`; admins run `hedge watch` |
| `hedge status` says `no config found` on the host | the CLI looks in `~/.hedge` | `export HEDGE_CONFIG=/etc/hedge/hedge.toml` |

## Upgrade and rollback

Replace the binary or the image tag and restart. Running answers get the
grace period. The witness format only ever gains optional fields, so a newer
Hedge reads and continues an older chain.

Rolling back: an older Hedge rejects config keys it does not know (a typo
must fail loudly), so remove newer options from `hedge.toml` first. A
version without segments reads only the active file – as an extract of the
chain – and ignores the closed ones.

There is never a moment with two instances. On Kubernetes that is what
`strategy: Recreate` is for; agents see a short interruption and retry.

## Corporate proxy and CA

Hedge reaches the LLM API with the usual environment:

- `HTTPS_PROXY` – a forward proxy for outgoing HTTPS.
- `NO_PROXY` – hosts that go direct. Put the OTLP collector and Presidio
  here if they are internal.
- The system CA store, or `SSL_CERT_FILE` pointing to a bundle. If your
  proxy inspects TLS, add the company CA to the store
  (`/usr/local/share/ca-certificates` + `update-ca-certificates` in a derived
  image), or mount a bundle that contains the public CAs **and** yours and
  point `SSL_CERT_FILE` at it. `SSL_CERT_FILE` replaces the store, it does
  not add to it.

The CLI never uses a proxy from the environment for a Hedge on the same
machine.

## Who can do what

- **Anyone who can write `hedge.toml` can run commands as the Hedge user**
  (`tools.notify_command`) and change every policy. Keep it root-owned,
  readable by the service.
- **A client token** lets its holder use the proxy under that name. It does
  not open the control API.
- **An admin token** opens the whole control API: status, approvals, the
  witness, rotation. There are no roles yet.
- **The local control token** does the same, without a name. It is readable
  only by the Hedge user.
- **Hedge passes provider credentials through** (`authorization`,
  `x-api-key`) and never stores or logs them. Developers therefore still
  hold their own provider credentials, and a developer with an API key can
  reach the provider without Hedge. Managed settings bind Claude Code, not
  the person. Closing that gap takes an egress rule on the network, or a
  Hedge that holds the provider key itself – which it does not do today.

## What has been verified, and what has not

Verified in a Linux sandbox with the real binary:

- 294 automated tests (238 unit, 53 integration, 3 that drive the binary
  with a stand-in for `docker`), among them: a full disk in the middle of a
  write (traffic continues, `/ready` 503, no torn line, clean continuation),
  recovery from a torn last line, rotation with readers following across it,
  named admins, client expiry and per-client budgets, the 413 path, remote
  reading of the witness, and Presidio starting, failing and returning
  against a stand-in.
- nginx 1.24 and Caddy 2.6 in front, with the configs in this repository:
  answers arrive as they are produced (with nginx buffering switched on for
  comparison they arrive at once, at the end); body limits; `/_hedge/*`
  for the admin network only; probes hidden; no listener on port 80. Caddy
  was run with the Caddyfile and the central config that `hedge deploy
  compose` writes; nginx before Presidio was merged in, with a config that
  has not changed since.
- Readiness with Presidio away: with Presidio findings enforced and
  `on_unavailable = "block"`, `/ready` and `hedge ready` say so, requests
  with text get 503, and the witness keeps one chain across a rotation.
- A held tool call approved by a named admin from "another machine" through
  nginx, with nothing but URL and token.
- Rotation under load: 12,000 entries in nine segments verify as one chain
  in 0.7 s.
- Shutdown: idle stop in milliseconds; a running answer finishes within the
  grace period; one that does not is recorded as cut off.
- `HTTPS_PROXY`, `NO_PROXY` and `SSL_CERT_FILE` are honoured.

Not verified:

- The image builds themselves (the sandbox could not pull base images),
  and Caddy, Grafana and Presidio as containers – so `docker compose up` of
  the generated directory has never run as a whole; `docker compose config`
  accepts it. What was run before Presidio was merged in: an image assembled
  by hand from the release binary with the same layout, user, entrypoint and
  health check – first start on an empty volume with a read-only root
  filesystem and no capabilities, restart, stop.
- A real Presidio together with the central setup. It ran natively against
  Hedge before the two lines of work were merged; since then only the
  stand-in and an absent Presidio.
- The Helm chart against a cluster. It was rendered with a stand-in for
  `helm template` and the manifests checked for structure, not installed.
- The systemd unit on a running systemd. `systemd-analyze verify` accepts
  it, and none of the system calls Hedge made in a traced run is denied by
  its filter.
- Windows. Rotation renames a file that is open.
- Grafana: the dashboard and the alert rules, including "no heartbeat",
  against a real Grafana.
- Claude Code with managed settings and `allowedProviders` against Hedge,
  and a subscription login through a central Hedge.
- Capacity on your hardware. One data point, not a sizing guide: release
  build, two shared cores, a mock upstream on the same machine, no TLS,
  eight connections, answers not streamed. With 200 KB request bodies (an
  agent sending its history) Hedge handled about 2,500 requests per second
  and added a median of 3 ms (95th percentile 5 ms); with 2 MB bodies about
  340 per second, median 23 ms. A witness entry for a plain request is about
  0.7 KB. Presidio and telemetry were off.
