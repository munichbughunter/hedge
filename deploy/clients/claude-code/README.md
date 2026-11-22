# Pointing Claude Code at a central Hedge

Two values per developer:

| Value | Where it comes from | Same for everyone? |
|---|---|---|
| `ANTHROPIC_BASE_URL` | the address of Hedge plus the upstream prefix, e.g. `https://hedge.example.com/anthropic` | yes |
| `ANTHROPIC_CUSTOM_HEADERS` | `x-hedge-client-token: <token>` from `hedge client add <name>` | no – one token per developer |

## By hand

```bash
export ANTHROPIC_BASE_URL=https://hedge.example.com/anthropic
export ANTHROPIC_CUSTOM_HEADERS="x-hedge-client-token: hc_…"
```

Or in `~/.claude/settings.json` (see [`settings.json`](settings.json)).
A value in a settings file wins over a shell export.

## For the whole organisation

Put the base URL into Claude Code's managed settings. A developer's own
settings and shell cannot override a managed value.

| OS | Path |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux, WSL | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

[`managed-settings.json`](managed-settings.json) is the file to distribute
(MDM, configuration management). `allowedProviders: ["customEndpoint"]`
makes Claude Code refuse any other endpoint, including Anthropic directly;
it needs a recent Claude Code version.

The token differs per person, so it stays in the developer's own
`~/.claude/settings.json`, or your device management writes it per machine.

## Check

In Claude Code, `/status` shows the base URL and where the settings come
from. On the Hedge side, the developer's first request appears under their
name: `hedge tail -f`.

## Good to know

- With only the base URL set, a developer's claude.ai login stays active:
  subscription limits and billing apply, and Hedge passes the credential
  through untouched. Hedge holds no provider key.
- While the base URL points at Hedge, Claude Code's Remote Control is
  unavailable, and settings managed in the claude.ai admin console do not
  reach these sessions.
- A private CA in front of Hedge (Caddy's `internal`, a company CA):
  `NODE_EXTRA_CA_CERTS=/path/to/root.crt`.
- Managed settings bind Claude Code, not the person. Someone with their own
  API key can still reach the provider with another tool. Closing that takes
  an egress rule on the network.

Source for the Claude Code side: the Claude Code documentation on
[LLM gateways](https://code.claude.com/docs/en/llm-gateway-rollout),
[managed settings](https://code.claude.com/docs/en/managed-settings) and
[network configuration](https://code.claude.com/docs/en/network-config).
The combination with Hedge – in particular `allowedProviders` with a base
URL that carries a path – has not been tested.
