# Hedge – AI Guard Proxy

Hedge sits between your coding agent (Claude Code, Codex, …) and the LLM API.
It sees every prompt before the provider does, finds secrets and personal data,
masks or blocks them according to your policy, and records every request in a
signed, tamper-evident log.

One binary, no runtime, written in Rust. Runs on a developer laptop or as a
central service.

```
Claude Code ──▶ Hedge (127.0.0.1:18765) ──▶ api.anthropic.com
                  │
                  ├─ detect   secrets (API keys, tokens, private keys), PII (e-mail, IBAN)
                  ├─ policy   observe | redact | block
                  └─ witness  signed hash chain of every request
```

## Quickstart (3 commands)

```bash
hedge init --claude-code   # config + signing key in ~/.hedge, points Claude Code at Hedge
hedge run                  # start the proxy
hedge tail -f              # watch requests as they happen
```

Without `--claude-code`, point your agent at Hedge yourself:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:18765/anthropic
export OPENAI_BASE_URL=http://127.0.0.1:18765/openai
```

Billing stays with whatever credential the agent already uses (subscription
login or API key). Hedge forwards the auth header and never reads, logs or
records it.

## What you see

`hedge run` prints a banner and one line per request:

```
14:35:19  WARN observed findings, forwarded unchanged upstream="anthropic" method="POST"
          path="/v1/messages" model="claude-sonnet-4-5" status=200 duration_ms=1240
          findings=2 where=anthropic_api_key(high)@messages[0].content, email(medium)@system[2].text
```

`hedge tail` shows the witness log for humans:

```
14:35:19  REDACT   anthropic  POST /v1/messages   claude-sonnet-4-5   200   1.2s  2 finding(s): Anthropic API key @ messages[0].content, e-mail address @ system[2].text
14:35:22  ok       anthropic  POST /v1/messages   claude-sonnet-4-5   200   0.9s
14:36:01  BLOCK    anthropic  POST /v1/messages   claude-sonnet-4-5   ---    3ms  1 finding(s): AWS access key ID @ messages[4].content[0].text
```

`hedge report --since 24h` aggregates for admins: requests by outcome, findings
by kind, where in the request they sit, by upstream and model, latency.

## Modes

| mode      | no findings | low / medium | high (API key, IBAN, private key) |
|-----------|-------------|--------------|-----------------------------------|
| `observe` | forward     | forward, log | forward, log                      |
| `redact`  | forward     | mask         | mask                              |
| `block`   | forward     | mask         | **reject with 403**               |

Start with `observe`, read `hedge report` for a few days, then move to `redact`
or `block`. A blocked request returns an error in the provider's error format,
so Claude Code shows the reason to the user:
`request blocked by hedge: 1 high-severity finding(s): anthropic_api_key`.

Masked text looks like `[REDACTED:anthropic_api_key]` – the model sees that
something was there and what kind.

## Configuration

`hedge init` writes a fully commented `~/.hedge/hedge.toml`. Every setting has
a default; an empty file is valid. Unknown keys are errors, so typos fail at
startup instead of silently doing nothing.

```toml
mode = "observe"

[server]
listen = "127.0.0.1:18765"

[[upstreams]]            # reachable as /<name>/...
name = "anthropic"
url = "https://api.anthropic.com"

[detectors]
secrets = true
pii = true

[severity]               # override per kind: low | medium | high
email = "low"

[allow]                  # your own infrastructure is not a finding
values  = ["me@example.com"]
domains = ["example.com"]

[log]
format = "pretty"        # json for central log systems
level  = "info"

[witness]
enabled = true
path = "~/.hedge/witness.jsonl"
key  = "~/.hedge/witness.key"
```

Config lookup order: `--config`, `$HEDGE_CONFIG`, `./hedge.toml`,
`~/.hedge/hedge.toml`.

## The witness

Every request becomes one line in an append-only JSONL file: timestamp,
upstream, method, path, model, mode, action, findings (kind, severity and JSON
path – never the text), SHA-256 of the body before and after masking, upstream
status, duration. Each entry carries the hash of the previous one and an
Ed25519 signature.

```bash
hedge verify                 # offline: hashes, sequence, signatures
hedge verify --witness export.jsonl --key witness.key.pub
```

A changed byte, a deleted line or an inserted entry fails verification and
names the entry. The public key (`witness.key.pub`) is all an auditor needs;
the signing key never leaves the machine that runs Hedge.

The witness contains no prompt text and no credentials, so it can be shipped
to a central store without becoming a leak itself.

## For admins

- `log.format = "json"` turns every log line into one JSON object for Loki,
  Datadog, Splunk, …
- `hedge report --json` gives the same aggregation as machine-readable JSON.
- `hedge doctor` checks config, port, upstream reachability, key, chain
  integrity and whether the agent is actually pointed at Hedge – exit code 1
  if anything needs fixing.
- `hedge check` validates a config without starting anything (use it in CI
  for policy changes).
- Policies live in TOML in version control; `deny_unknown_fields` makes a
  typo a startup failure, not a silent gap.

## Commands

```
hedge run                      start the proxy (default)
hedge init [--claude-code]     create config, keys, witness
hedge check                    validate and summarize the config
hedge tail [-n 20] [-f]        last witness entries, human-readable (--json for raw)
hedge report [--since 24h]     aggregate across requests (--json)
hedge verify                   verify the witness chain offline
hedge doctor                   check the whole setup
```

## Status

v0.1.0 – observe, redact and block work end-to-end with Claude Code.
Not yet: streaming responses pass through buffered (output arrives in one
piece), no OpenTelemetry export yet, no response inspection.

## Development

```bash
cargo test            # unit + integration tests (mock upstream)
cargo clippy --all-targets -- -D warnings
cargo fmt
```

MIT licensed. Built by [Doering IT Consulting](https://doering-itconsulting.de).
