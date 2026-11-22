# Hedge zentral betreiben

Dieses Verzeichnis startet Hedge und Presidio auf einem Host. Entwickler
bekommen eine URL und ein Token; alles andere liegt hier.

```
Agent ──https──▶ Reverse Proxy ──▶ hedge ──▶ api.anthropic.com / api.openai.com
                                     │
                                     └──▶ presidio   (internes Netz, kein Port nach außen)
```

## Starten

1. **Images.** Die Namen stehen in `.env`. Solange sie nicht in einer
   Registry liegen, baust du sie selbst:

   ```
   docker compose build presidio                      # aus ./presidio, einige Minuten
   docker build -t <HEDGE_IMAGE aus .env> <Pfad zum hedge-Repo>
   ```

2. **Hoch damit.**

   ```
   docker compose up -d
   docker compose ps                                  # hedge und presidio: healthy
   curl -s http://127.0.0.1:18765/ready               # {"ready":true}
   ```

   Hedge wartet beim Start, bis Presidio seine Sprachmodelle geladen hat.

3. **Steuer-Token holen** (für `hedge status`, Freigaben):

   ```
   docker compose exec hedge cat /var/lib/hedge/control.token
   export HEDGE_URL=http://127.0.0.1:18765 HEDGE_CONTROL_TOKEN=<token>
   hedge status
   ```

   Die Zeile `presidio ● ready  de, en` sagt, dass die Namenserkennung läuft.

## Entwickler anbinden

Ein Client pro Person, angelegt auf diesem Host:

```
hedge --config hedge/hedge.toml client add <name>
```

Der Befehl zeigt das Token einmal und die zwei Zeilen, die der Entwickler
braucht. Hedge übernimmt den neuen Client binnen Sekunden. Sobald alle ein
Token haben: `require_client = true` in `hedge/hedge.toml`.

Für Claude Code sind es zwei Einstellungen:

```
ANTHROPIC_BASE_URL=https://<dein-hedge-host>/anthropic
ANTHROPIC_CUSTOM_HEADERS="x-hedge-client-token: hc_…"
```

## TLS

Hedge spricht HTTP und lauscht deshalb nur auf `127.0.0.1` (`HEDGE_BIND` in
`.env`). Davor gehört ein Reverse Proxy, der TLS terminiert. Er muss:

- Antworten ungepuffert durchreichen (Hedge streamt),
- mindestens 600 s auf Antworten warten und Bodies bis 10 MiB annehmen,
- `/_hedge/*` nur aus dem Admin-Netz zulassen, `/health` und `/ready` nur intern.

## Scharfstellen

Am Anfang beobachtet Hedge nur. In `hedge/hedge.toml` sind die Schalter mit
`[scharf]` markiert; die Reihenfolge, die sich bewährt:

1. Ein paar Tage laufen lassen, dann `hedge report` (im Container:
   `docker compose exec hedge hedge report`). Dort steht, was Presidio
   gefunden hätte – auch die Fehlalarme.
2. `mode = "redact"`: eingebaute Funde (Keys, E-Mail, IBAN) werden maskiert.
3. `[presidio] enforce = true`: Namen und Telefonnummern ebenfalls. Ab hier
   gilt `on_unavailable = "block"`: Fällt Presidio aus, lehnt Hedge Anfragen
   mit prüfbarem Text ab (HTTP 503), statt sie ungeprüft weiterzuleiten.

## Betrieb

| Frage | Antwort |
|---|---|
| Läuft alles? | `docker compose ps`, `hedge status`, `GET /ready` |
| Presidio antwortet nicht | Im Witness steht `presidio_unavailable` mit Grund und Zeitpunkt, später `presidio_ready`. Logs: `docker compose logs presidio` |
| Mehr Durchsatz | `PRESIDIO_WORKERS` in `.env` (pro Prozess rund 0,7 GB und ein Kern) |
| Dashboard und Alerts | `COMPOSE_PROFILES=observability` in `.env`, `[telemetry] enabled = true`, dann `docker compose up -d`. Grafana: http://127.0.0.1:3000, Ordner „Hedge“. Der Alert „Presidio is not ready“ meldet einen Ausfall. |
| Aktualisieren | Neues Hedge installieren, `hedge deploy compose -o <dieses Verzeichnis> --force` (die `hedge.toml` bleibt), Images bauen oder ziehen, `docker compose up -d` |
| Eigene Registry | Images spiegeln, Namen in `.env` ändern |

Hedge ist ein Einzelinstanz-Dienst: genau ein Container schreibt die
Witness-Kette. Nicht skalieren, nicht parallel starten.

## Was in diesem Verzeichnis liegt

| Datei | Zweck |
|---|---|
| `docker-compose.yml` | Hedge, Presidio, optional Grafana |
| `.env` | Image-Namen, Port, Zahl der Presidio-Prozesse |
| `hedge/hedge.toml` | die Policy; wird ohne Neustart neu geladen |
| `presidio/` | Build-Kontext des Presidio-Images (Deutsch und Englisch) |
| `grafana/` | Dashboard und Alert-Regeln |
