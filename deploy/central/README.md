# Hedge zentral betreiben

Dieses Verzeichnis startet Hedge und Presidio auf einem Host. Entwickler
bekommen eine URL und ein Token; alles andere liegt hier.

```
Agent ──https──▶ Caddy oder dein Reverse Proxy ──▶ hedge ──▶ api.anthropic.com / api.openai.com
Admin ──https──▶   (/_hedge/* nur aus dem Admin-Netz) ──▶ hedge:18766   Steuer-API
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

3. **Steuer-Token holen** (für `hedge status`, Freigaben). Die Steuer-API
   hat ihren eigenen Port, 18766; am Port der Agents gibt es `/_hedge/*`
   nicht.

   ```
   docker compose exec hedge cat /var/lib/hedge/control.token
   export HEDGE_URL=http://127.0.0.1:18766 HEDGE_CONTROL_TOKEN=<token>
   hedge status
   ```

   Die Zeile `presidio ● ready  de, en` sagt, dass die Namenserkennung läuft.

## Admins

Das Token aus Schritt 3 gehört dem Host. Menschen bekommen ein eigenes, mit
Namen:

```
hedge --config hedge/hedge.toml admin add <name>
```

Der Befehl zeigt das Token einmal. Jede Freigabe und jede Ablehnung steht
danach mit diesem Namen im Witness. Vom eigenen Rechner braucht ein Admin
nur Adresse und Token, keine Config und keinen Zugriff auf Dateien:

```
export HEDGE_URL=https://<dein-hedge-host> HEDGE_CONTROL_TOKEN=ha_…
hedge status      hedge approvals     hedge approve <id>
hedge tail -f     hedge report        hedge watch
```

Das geht nur aus den Netzen in `HEDGE_ADMIN_CIDRS` (siehe TLS).

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
`.env`). Davor gehört etwas, das TLS terminiert. Zwei Wege:

**Caddy aus diesem Verzeichnis.** In `.env`:

```
COMPOSE_PROFILES=tls                # mit Grafana: tls,observability
HEDGE_DOMAIN=hedge.example.com      # der Name, den Entwickler benutzen
HEDGE_TLS=internal                  # oder dein Zertifikat, oder Let's Encrypt
HEDGE_ADMIN_CIDRS=10.0.10.0/24      # wer /_hedge/* erreichen darf
```

Dann `docker compose up -d`. Mit `HEDGE_TLS=internal` stellt Caddy das
Zertifikat aus seiner eigenen CA aus; Entwickler müssen deren Wurzel kennen
(`docker compose exec caddy cat /data/caddy/pki/authorities/local/root.crt`,
bei Claude Code über `NODE_EXTRA_CA_CERTS`). Für ein eigenes Zertifikat
kommen die beiden Dateien nach `./certs`. `hedge deploy compose --tls`
schaltet das Profil gleich ein.

**Dein eigener Reverse Proxy.** Er muss:

- Antworten ungepuffert durchreichen (Hedge streamt),
- mindestens 600 s auf Antworten warten (ein angehaltener Tool-Aufruf wartet
  auf einen Menschen),
- Bodies mindestens so groß annehmen wie `server.max_body_mb` (Standard 10),
- die API nicht von HTTP auf HTTPS umleiten (ein Redirect kann den Body
  kosten),
- `/_hedge/*` nur aus dem Admin-Netz an Port 18766 weiterreichen, `/health`
  und `/ready` nur intern zulassen,
- Header unverändert durchreichen.

Ein nginx-Beispiel und die Begründungen stehen im Repository unter
`deploy/proxy/nginx.conf` und `docs/operations.md`.

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
| Der Witness wächst | `rotate_mb` in `hedge/hedge.toml` schließt ab dieser Größe ein Segment, die Kette läuft weiter; von Hand: `hedge rotate`. Geschlossene Segmente (`witness.<von>-<bis>.jsonl`) lassen sich wegsichern. `hedge verify` prüft alle zusammen. |
| Beenden und Neustart | `docker compose stop` gibt laufenden Antworten 30 s (`shutdown_grace_secs`); was dann noch läuft, steht als abgebrochen im Witness. |
| Hedge selbst ist weg | Der Alert „no heartbeat“ meldet es; alle anderen Regeln sehen bei einem Ausfall nur Ruhe. |
| Dashboard und Alerts | `COMPOSE_PROFILES=observability` in `.env`, `[telemetry] enabled = true`, dann `docker compose up -d`. Grafana: http://127.0.0.1:3000, Ordner „Hedge“. Der Alert „Presidio is not ready“ meldet einen Ausfall. |
| Aktualisieren | Neues Hedge installieren, `hedge deploy compose -o <dieses Verzeichnis> --force` (die `hedge.toml` bleibt), Images bauen oder ziehen, `docker compose up -d` |
| Eigene Registry | Images spiegeln, Namen in `.env` ändern |

Hedge ist ein Einzelinstanz-Dienst: genau ein Container schreibt die
Witness-Kette. Nicht skalieren, nicht parallel starten.

## Was in diesem Verzeichnis liegt

| Datei | Zweck |
|---|---|
| `docker-compose.yml` | Hedge, Presidio, optional Caddy und Grafana |
| `.env` | Image-Namen, Ports, Profile, TLS, Zahl der Presidio-Prozesse |
| `Caddyfile`, `certs/` | TLS vor Hedge (Profil `tls`) |
| `hedge/hedge.toml` | die Policy; wird ohne Neustart neu geladen |
| `presidio/` | Build-Kontext des Presidio-Images (Deutsch und Englisch) |
| `grafana/` | Dashboard und Alert-Regeln |
