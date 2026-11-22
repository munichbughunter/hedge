# Hedge – AI Guard Proxy

Hedge sits between your coding agent (Claude Code, Codex, …) and the LLM API.
It sees every prompt before the provider does and every answer before the
agent does. It finds secrets and personal data, masks or blocks them, checks
the tool calls the model asks for, and records everything in a signed,
tamper-evident log.

One binary, no runtime, no SDK, no hooks. Written in Rust. Runs on a developer
laptop or as a central gateway.

```
Claude Code ──▶ Hedge (127.0.0.1:18765) ──▶ api.anthropic.com
                  │
   prompt  ──▶    ├─ detect    secrets (API keys, tokens, private keys), PII (e-mail, IBAN; names via Presidio)
                  ├─ policy    observe | redact | block · model allowlist · token budgets
   answer  ◀──    ├─ tools     every tool call the model requests: allow | deny | hold for approval
                  ├─ witness   signed hash chain of every request, tool call and config change
                  └─ telemetry OpenTelemetry traces + metrics → Grafana, alerts
```

## Quickstart (3 commands)

```bash
hedge init --claude-code   # config, signing key, control token in ~/.hedge; points Claude Code at Hedge
hedge run                  # start the proxy
hedge watch                # watch live and approve by key (or: hedge tail -f)
```

Without `--claude-code`, point your agent at Hedge yourself:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:18765/anthropic
export OPENAI_BASE_URL=http://127.0.0.1:18765/openai
```

Answers are streamed through as they arrive; Claude Code feels the same with
and without Hedge. Billing stays with whatever credential the agent already
uses. Hedge forwards the auth header and never reads, logs or records it.

## What you see

```
$ hedge tail -f
15:46:01  ok       anthropic  claude-sonnet-4-5   3f2a9c1e  200   2.1s  1.2k→340  ⚙ Read ×2, Grep
15:46:09  REDACT   anthropic  claude-sonnet-4-5   3f2a9c1e  200   3.4s  1.4k→512
          │ prompt  Anthropic API key …a1b2  messages[0].content[3].text
          │ prompt  e-mail address j…@customer.com  messages[0].content[3].text
15:46:14  redact   anthropic  claude-sonnet-4-5   3f2a9c1e  200   2.2s  1.5k→88
          │ prompt  2 seen before in this session (history resent with every request)
15:46:20  STOP     anthropic  claude-sonnet-4-5   3f2a9c1e  200   1.9s  1.4k→96
          │ tool    Bash  rm -rf ~/  ✗ denied HEDGE-SHELL-001
15:46:41  HOLD     anthropic  claude-sonnet-4-5   3f2a9c1e  200   2.0s  1.4k→120
          │ tool    Bash  git push --force origin main  ⏸ needs approval HEDGE-SHELL-003  → reply `approve 00f4cd` in the session, or: hedge approve 00f4cd
15:46:55  ·        ✓ 00f4cd approved via chat · Bash · HEDGE-SHELL-003
15:47:02  BLOCK    anthropic  claude-sonnet-4-5   3f2a9c1e  ---    3ms
          │ why     1 high-severity finding(s): aws_access_key_id
```

One line per request: time, outcome, upstream, model, session, status,
duration, tokens in→out, tools called. Anything that needs your attention
gets its own indented line. Each finding carries a masked hint
(`j…@customer.com`, `…a1b2`) so you can tell which address or key it was.
Agents resend the whole conversation with every request; a finding is news
once per session and afterwards only folded into "seen before" (it is still
masked every time, but not counted or alerted again). `--alerts` shows only those, `-v` shows every
finding and every tool call, `--session <id>` follows one agent session.

| command | answers |
|---|---|
| `hedge watch` | Everything at a glance, live – and approve or deny with one key |
| `hedge tail -f` | What is happening right now? (plain lines, for pipes and logs) |
| `hedge sessions` | Which agent sessions ran, how many tokens, findings, tool calls? |
| `hedge report --since 24h` | Totals for admins: outcomes, findings by kind and location, tools, rules, clients, models, latency |
| `hedge status` | Is it running, in which mode, anything waiting for approval, budget used? |
| `hedge approvals` | Which tool calls are waiting for a yes, and how do I give it? |
| `hedge doctor` | Is everything wired up correctly? What do I fix? |
| `hedge check` | Is this config valid and what does it mean? |
| `hedge rules` | Which tool rules are active? `hedge rules test Bash 'git push -f'` tries one |

Every listing takes `--json`.

## Watch: the terminal view

```
$ hedge watch
 H E D G E   OVERVIEW   LIVE   APPROVALS 1   PERMISSIONS     WAITING FOR YOU 1   ● LIVE  CHAIN ✓ 23
 ┌────────────────────────────────────────────────────────────────────────────────────────────────┐
 │ HOLD   Bash · 08f8f057 · git push --force origin main   expires in 4:57      a approve  d deny │
 └────────────────────────────────────────────────────────────────────────────────────────────────┘
 ┌ SESSIONS ─────────────────────────────────────────────────────────────── 6 sessions · 1 active ┐
 │ SESSION     STATE      REQS  TOOLS  BLOCKED   HELD  FLAGGED  FINDINGS    TOKENS  WITNESS       │
 │▌08f8f057    ● active      6      5        0      5        0         0      9.6k   HOLD         │
 │ 6d0557ef    ○ idle        3      2        0      0        0         3      4.9k  ✓ chain       │
 │ 468fb233    ○ idle        2      2        2      0        0         0      3.2k  ✓ chain       │
 │                                                                                                │
 │ REQUESTS       BLOCKED        HELD           FLAGGED        NEW FINDINGS   TOKENS TODAY        │
 │ 16             2              7              0              3              25.6k               │
 └────────────────────────────────────────────────────────────────────────────────────────────────┘
 ┌ LIVE ──────────────────────────────────────────────────────────────────────────── newest first ┐
 │ 20:32:09  08f8f057   HOLD   Bash          git push --force origin main        HEDGE-SHELL-003  │
 │ 20:28:03  6d0557ef  REDACT  prompt        e-mail address b…@files.example · messages[0].content│
 │ 20:18:02  468fb233  STOP    Read          ~/.hedge/witness.key          HEDGE-CRED-001 · denied│
 └────────────────────────────────────────────────────────────────────────────────────────────────┘
  ↑↓ select   ↵ open session   a/d approve/deny   f alerts only   / filter   1-4 tabs   ? help   q quit
```

Four tabs, each answering one question:

- **Overview (`1`) – what is going on?** One row per agent session, newest
  activity first: requests, tool calls, what was blocked, held, flagged,
  found; counters below, the live stream underneath. `enter` opens a
  session.
- **Live (`2`) – what exactly happened?** Three panes: the sessions on the
  left (`←` `→` switches, with the tool mix below), the tape in the middle,
  the selected record on the right. The tape spells every request out row
  by row – `MODEL`, each finding (`FIND`), each tool call (`TOOL`, or
  `HOLD` / `DENY` / `FLAG` when a rule touched it), each answer to an
  approval – with what came of it in the `STATUS` column. `n` / `N` jumps
  from decision to decision, `f` narrows the tape (all, alerts, decisions,
  approvals). An opened session shows its facts and the commands that
  export and verify it as evidence.
- **Approvals (`3`) – what is waiting for me?** One card per held call: the
  command, the rule in words, the id, when it expires, and both ways to
  answer – `a` / `d` right there, or `hedge approve <id>` from anywhere.
  Below: every answer so far, who gave it and how.
- **Permissions (`4`) – where did hedge step in, and what came of it?**
  Every decision that was not a plain allow – held, denied and flagged tool
  calls, blocked and masked prompts – with its outcome: waiting, blocked,
  ran flagged, masked, approved (and whether the call then ran), rejected,
  expired. `←` `→` narrows to one group, `enter` opens the session.

A held tool call appears as a bar at the top of every tab, rings the
terminal bell once, and is the only filled amber on the screen. `a` asks
once more (`y`) and then approves exactly the request shown – the list may
change between two keys, the confirmation cannot. `d` denies at once. The
header verifies the witness as it grows (`CHAIN ✓ n records`); a modified
or missing entry turns it red and marks its session. `/` filters by
session, client, model, tool or rule; `?` lists the keys.

`hedge watch` reads the witness file directly, so sessions and history are
there even while the proxy is stopped; approvals need the running proxy
(`● LIVE`). With `--url` and `--token` it reaches a Hedge on another
machine – approvals only, the witness stays where it is written.

Colours follow the terminal: 24-bit where it is announced
(`COLORTERM=truecolor`), 256 or 16 colours otherwise, none with `NO_COLOR`.
Narrow terminals drop columns (model, client, start, tokens) and side
panes before they cut numbers or the tape.

## Prompts: observe, redact, block

| mode      | no findings | low / medium | high (API key, IBAN, private key) |
|-----------|-------------|--------------|-----------------------------------|
| `observe` | forward     | forward, log | forward, log                      |
| `redact`  | forward     | mask         | mask                              |
| `block`   | forward     | mask         | **reject with 403**               |

Hedge scans every string in the request JSON, wherever it sits (system
prompt, messages, tool results), and tells you the JSON path of each finding.
Masked text looks like `[REDACTED:anthropic_api_key]`. A blocked request
returns an error in the provider's format, so Claude Code shows the reason.

Your own infrastructure is not a finding:

```toml
[allow]
values  = ["me@example.com"]
domains = ["example.com"]

[severity]
email = "low"          # per kind: low | medium | high
```

### Names and phone numbers: Presidio

The built-in detectors find what has a fixed format. Names do not have one.
For those Hedge uses [Presidio](https://github.com/data-privacy-stack/presidio)
with a German and an English language model. It is a feature of Hedge, not a
second product to run:

```
$ hedge presidio enable
  ✓ docker        running (OrbStack)
  ✓ image         ghcr.io/munichbughunter/hedge-presidio:0.1.0 (de, en · arm64 · 1.2 GB)
  ✓ container     hedge-presidio on 127.0.0.1:5002 (created)
  ✓ ready         after 11.2s · presidio 2.2.366 · de_core_news_md, en_core_web_md
  ✓ self-test     "Jörg Müller, Tel. +49 170 …" → person name, phone number (14 ms)
  ✓ config        ~/.hedge/hedge.toml: [presidio] enabled = true, managed = true
  ✓ hedge         picked up the change, no restart needed
```

After that `hedge run` starts the container with it, and `hedge status`,
the banner and `hedge watch` show `presidio ● ready`. It needs Docker or
Podman and about 1 GB of memory; without it everything else works as before.
Until the image is published, `hedge presidio enable --build` builds it on
your machine from files inside the binary (the same files are in
`deploy/presidio`).

| command | what it does |
|---|---|
| `hedge presidio enable` | fetch the image, start the container on loopback, wait for the models, self-test, then write the config. A failed step names the command that fixes it and leaves the config alone |
| `hedge presidio status` | ready or not, why, and what helps. With `--url` it asks a central Hedge |
| `hedge presidio test "<text>"` | what Presidio finds in a text, what Hedge would report and what it drops, and the masked result |
| `hedge presidio logs` | the container's output |
| `hedge presidio upgrade` | recreate the container from the image that belongs to this Hedge version |
| `hedge presidio disable` | switch it off and stop the container (`--remove` deletes it) |

```toml
[presidio]
enabled = true
managed = true                    # hedge starts the container itself; false = `url` is someone else's service
languages = ["de", "en"]          # each text is analysed once, in the language it is written in
entities = ["PERSON", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE"]
scope = ["user", "tool_result"]   # also: system, tools, assistant, tool_use
enforce = false                   # false: report only. true: mask or block like built-in findings
on_unavailable = "allow"          # or "block": nothing leaves that Presidio could not check
```

What to know before switching `enforce` on:

- **Start by watching.** With `enforce = false` findings are recorded as
  `(reported only)` and nothing is changed. `hedge report` shows what would
  have been masked, with initials (`J… M…`) so you can tell a real name from
  a false alarm. Put your own terms into `[allow] values`.
- **Language models are generous with names.** On source code and logs a raw
  Presidio marked `Mutex`, `prometheus` and `t.bold` as people. Hedge drops
  what cannot be a name by its spelling and, by default, single words without
  a title in front (`Wagner` no, `Frau Wagner` and `Sabine Wagner` yes;
  `single_names = true` reports them all). On a small mixed sample of code,
  logs and chat (160 KB) that took about 240 raw name hits down to about 40,
  nine in ten of them real. Names in tables (CSV rows) were not found at all.
- **A phone number needs a word in front of it** (`Tel.`, `phone`): without
  one it stays below the threshold, because timestamps and ids look the same.
  A long number that happens to pass the card checksum is reported as a
  credit card.
- **Scope.** Only what the human typed and what tools returned goes to
  Presidio. The agent's system prompt, tool definitions and image data never do.
- **Speed.** Presidio reads about 50 KB of text per second and process.
  Hedge caches per piece of text, so an agent's growing history is analysed
  once; in a running session a request costs milliseconds. A request waits at
  most `budget_ms` (10 s). What is not done by then finishes in the
  background and is in the cache for the next request.
- **Outages.** Presidio is `starting`, `ready` or `unavailable`. Ready means
  it answers *and* found the name in a test sentence for every configured
  language, so a Presidio without a German model is not ready for
  `languages = ["de", "en"]`. While it is away no request waits for a
  timeout. With `on_unavailable = "allow"` requests go on and carry the flag
  `presidio_unavailable`; with `"block"` (and `enforce = true`, mode not
  observe) Hedge answers 503 and sends nothing. Each change of state is a
  witness event (`presidio_unavailable`, `presidio_ready`), so the chain
  shows from when to when no name detection ran.

## Answers: tool calls, tokens, leaks

Hedge reads the model's answer while streaming it through:

- **Tool calls.** Every tool the model asks the agent to run (Bash, Write, …)
  is recorded with a short, masked preview and checked against rules.
- **Tokens.** Input, output and cache reads per request, session, client.
- **Leaks.** Secrets in model output are reported (observe only: what has
  been streamed cannot be taken back).

### Tool rules: allow, deny, hold

```toml
[tools]
enforce = true        # false (default): hits are only flagged
packs = ["destructive-shell", "credential-files", "exfiltration"]

[[tools.rules]]       # your rules come first; first match wins
id = "no-prod-db"
tool = "Bash"
match = "psql .*prod"
action = "hold"       # allow | deny | hold
reason = "production database needs a human"
```

- **deny** – the tool call never reaches the agent. In its place the model
  reads why it was blocked and is told not to retry, so the turn ends
  cleanly instead of with an API error.
- **hold** – the call needs a human yes. Hedge asks where you already are:
  in the agent session.

  ```
  ⏸ Hedge paused this tool call. It needs your approval before it runs.

      Bash: git push --force origin main

  Rule HEDGE-SHELL-003: force push rewrites remote history

  To allow it once, reply with exactly:  approve 00f4cd
  To refuse it, reply with:  deny 00f4cd
  ```

  Reply `approve 00f4cd` and the model issues the call again; exactly that
  call passes, once. `hedge approve 00f4cd` in a terminal does the same
  (then tell the agent to continue). Anything else, or five minutes of
  silence, and it does not run. The question, the decision and the route
  it came by (chat or control API) are in the witness.

Built-in packs (8 rules, each with a stable id such as `HEDGE-SHELL-001`):
recursive delete of `/` or `~`, formatting disks, force pushes, piping
downloads into a shell, touching SSH/cloud credentials or Hedge's own key,
uploading local files. `hedge rules` lists them.

Be clear about what this is: rules match text. They catch mistakes and
obvious overreach and leave a signed record; a model that sets out to evade
them can rephrase a command. It is a tripwire, not a sandbox.

Hedge also cross-checks: a tool result the agent reports for a call Hedge
never saw the model request is flagged (`unwitnessed_tool_result`).

#### Approvals

```toml
[tools]
approve_in_chat = true          # default: ask in the session
approval_timeout_secs = 300     # how long a request (and an unused yes) is valid

# tell someone, locally or in the team channel
notify_command = "terminal-notifier -title Hedge -message \"$HEDGE_TOOL: $HEDGE_PREVIEW ($HEDGE_APPROVAL_ID)\""
notify_webhook = "https://hooks.slack.com/services/…"
```

- An approval is bound to the session, the tool and its input. For shell
  tools that is the command (not its description or timeout); for everything
  else the whole input. A different command asks again.
- Only what the human typed counts: a message that is exactly
  `approve <id>`. The same words inside a tool result (file contents,
  command output) or a longer sentence do nothing, and neither does a reply
  from another session.
- `approve_in_chat = false` is for a second pair of eyes: the call then
  waits in the stream until someone runs `hedge approve <id>` (from this
  machine or, with `--url`, from another). The session shows a notice with
  the id while it waits, `hedge watch` and `hedge tail -f` show it at once
  and ring the terminal bell, and without a decision the call is rejected.
- `notify_command` gets `HEDGE_APPROVAL_ID`, `HEDGE_TOOL`, `HEDGE_PREVIEW`,
  `HEDGE_RULE`, `HEDGE_REASON`, `HEDGE_SESSION`, `HEDGE_CLIENT` as
  environment variables (values are data, never part of the command line).
  `notify_webhook` receives a JSON POST with a Slack-compatible `text` and
  the full request under `approval`.

## The witness: record and prove

Every request becomes one line in an append-only JSONL file: time, upstream,
model, session, client, mode, action, findings (kind, severity, JSON path –
never the text), SHA-256 of the body before and after masking, tokens, tool
calls with rule and decision, status, duration. Starts, stops, every config
reload and every approval decision are entries too. Each entry carries the hash of the previous
one and an Ed25519 signature.

```bash
hedge verify                              # offline: hashes, sequence, signatures
hedge head                                # current head as  <seq>:<hash>  – keep it somewhere else
hedge verify --anchor <seq>:<hash>        # also detects a chain whose end was cut off
hedge export --session 3f2a9c1e -o run.json   # evidence for one agent session
hedge verify --bundle run.json            # anyone can check it, offline
```

A changed byte, a deleted line or an inserted entry fails verification and
names the entry. The witness contains no prompt text and no credentials, so
it can be collected centrally. Two things are deliberately human-readable and
can be switched off: tool previews (first 120 characters of the command or
path, secrets masked; `[witness] tool_preview = false`) and finding hints
(first letter and domain of an e-mail, last four characters of a secret;
`[witness] hints = false`).

With telemetry on, every span carries the sequence number and hash of its
witness entry – your tracing backend becomes an external anchor for free.

## For admins

**The whole setup in one directory.** `hedge deploy compose` writes a Compose
project from the binary: Hedge, Presidio on an internal network that nothing
else can reach, optionally Grafana with dashboard and alerts, a central
`hedge.toml` and a README with the steps.

```bash
hedge deploy compose --client alice --observability   # → ./hedge-central, prints alice's token once
cd hedge-central && docker compose up -d
curl -s 127.0.0.1:18765/ready                          # {"ready":true} once presidio is up
```

Developers get a URL and a token. They never see Presidio; `hedge status
--url … --token …` tells them whether it is active. The generated config
starts in observe mode with `on_unavailable = "block"` prepared, so that
switching `enforce` on later also makes an outage fail closed. `GET /ready`
(no token) is 200 only while Hedge serves requests the way the config
demands; `hedge ready` is the same check as a command, for container
health checks. `/health` only says the process is alive.

**Central gateway by hand.** Listen on a network address, require client tokens:

```toml
[server]
listen = "0.0.0.0:18765"
require_client = true
```

```bash
hedge client add alice     # prints a token once, stores only its hash, live without restart
```

Each developer sets `ANTHROPIC_BASE_URL` and
`ANTHROPIC_CUSTOM_HEADERS="x-hedge-client-token: <token>"`. Every witness
entry, metric and report line then carries the client name. Terminate TLS in
front of Hedge (ingress, reverse proxy).

**Policy without restarts.** Hedge reloads `hedge.toml` when it changes (or
on SIGHUP). A broken config is rejected and the previous one stays active.
Both outcomes are witnessed. Unknown keys are errors, so a typo fails loudly.

**Guard rails.**

```toml
[models]
allow = ["claude-sonnet-*", "claude-haiku-*"]

[budget]
daily_tokens   = 2_000_000    # per client and day (input without cache reads + output)
session_tokens = 500_000      # per agent session
```

**Observability.** `[telemetry] enabled = true` exports OTLP/HTTP traces and
metrics. One span per request, all requests of an agent session in one
trace. Metrics: `hedge_requests`, `hedge_findings`, `hedge_tool_calls`,
`hedge_tokens`, `hedge_request_duration_ms`, `hedge_witness_errors`, and
for Presidio `hedge_presidio_up`, `hedge_presidio_texts` (analyzed, cached,
failed), `hedge_presidio_duration_ms`, `hedge_presidio_unscanned`.

```bash
docker compose -f deploy/compose/docker-compose.yml up -d   # Grafana + Tempo + Prometheus
open http://localhost:3000                                  # Dashboards → Hedge
```

The stack ships a dashboard and five alert rules (high-severity finding,
tool call stopped, witness write failed, Presidio not ready, requests that
passed without the Presidio check). `log.format = "json"` gives one
JSON object per request for Loki, Datadog or Splunk.

**Remote control.** `hedge status|approvals|approve|deny` and `hedge presidio
status` take `--url` and `--token` (or `HEDGE_URL`, `HEDGE_CONTROL_TOKEN`) to
talk to a central Hedge.

## Configuration

`hedge init` writes a fully commented `~/.hedge/hedge.toml`. Every setting has
a default; an empty file is valid. Hedge always reads `~/.hedge/hedge.toml`,
wherever you start it; `--config <file>` or `$HEDGE_CONFIG` point it somewhere
else. `hedge run` prints which file it uses. `hedge.example.toml` in this
repository is the same template for reading.

## Compared with hook-based tools

Tools like Tracekit attach to an agent's lifecycle hooks and sign what the
agent reports about itself. Hedge sits on the wire instead:

- **No hooks, no SDK.** Any agent that can set a base URL works. The agent
  cannot skip Hedge the way a hook can be skipped.
- **Sees the prompt.** Secrets and PII are masked before they leave the
  machine. Hook-based tools see tool calls, not what is sent to the model.
- **Sees what the model asked for,** not what the agent says it did, and
  flags the difference.

What Hedge does not do (yet): independent witnesses cosigning the chain,
kernel-level or network egress sensors, replaying a run to explain why an
action happened, approving from inside Slack or with passkeys (Slack gets
the notification, the yes still comes from the session or the CLI), an executor that
holds credentials the agent never sees. Tool-call visibility and token
accounting understand the Anthropic Messages API; OpenAI-format answers
are streamed through with token accounting only. Request inspection works
for every JSON API.

## Limits worth knowing

- A local agent runs as you. It can read `~/.hedge/control.token` and approve
  its own held call, and a compromised agent process could put `approve <id>`
  into the conversation itself. The `credential-files` pack denies tool calls
  that touch Hedge's files, which stops the direct route, not every route.
  Approving in the session guards against a model that overreaches, not
  against an agent you cannot trust. For real separation run Hedge centrally
  with `approve_in_chat = false` and approve from another machine.
- Cutting off the newest witness entries is invisible in the file alone;
  that is what `hedge head`, `--anchor` and the telemetry export are for.
- Findings in model answers are reported, not masked.
- Presidio receives prompts in clear text and has no login of its own. Keep
  it on loopback (what `hedge presidio enable` does) or on a network only
  Hedge can reach (what `hedge deploy compose` does). `hedge doctor` objects
  to a `presidio.url` on a foreign host.
- Name detection is a language model's guess. It misses names (tables, odd
  spellings, single first names by default) and reports things that are not
  names. Treat it as a second net under the regex detectors, and look at
  `hedge report` before you let it mask anything.

## Development

```bash
cargo test            # 218 unit tests, 40 integration tests against a mock LLM API and a
                      # fake Presidio, 3 tests that drive the binary with a fake docker
cargo clippy --all-targets -- -D warnings
cargo fmt
```

MIT licensed. Built by [Doering IT Consulting](https://doering-itconsulting.de).
