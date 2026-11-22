//! Zeichnet den Zustand der [`App`] – und sonst nichts. Keine Ein-/Ausgabe,
//! keine Uhr: `now` kommt von außen, damit sich jede Ansicht im Test gegen
//! einen festen Zeitpunkt rendern lässt.

use chrono::{DateTime, Local};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState};

use super::model::{
    Decision, Fate, Filter, NO_SESSION, Ruling, SessionRow, Summary, TapeRow, Tone, Verdict,
    session_key, summary,
};
use super::theme::Theme;
use super::{App, Chip, Link, Mode, Tab, TapeFilter};
use crate::approvals::ApprovalInfo;
use crate::cli::{human_count, human_duration, parse_ts, truncate};
use crate::witness::Entry;

/// Darunter wird es unleserlich; dann lieber ein klarer Hinweis.
const MIN_WIDTH: u16 = 72;
const MIN_HEIGHT: u16 = 14;
/// Eine Session gilt als aktiv, wenn ihre letzte Anfrage so jung ist.
const ACTIVE_SECS: i64 = 120;
const TOAST_SECS: u64 = 6;

pub fn draw(f: &mut Frame, app: &App, t: &Theme, now: DateTime<Local>) {
    let screen = f.area();
    f.render_widget(Block::new().style(t.base()), screen);
    if screen.width < MIN_WIDTH || screen.height < MIN_HEIGHT {
        let msg = format!(
            "hedge watch needs at least {MIN_WIDTH}×{MIN_HEIGHT} – this terminal is {}×{}",
            screen.width, screen.height
        );
        f.render_widget(Paragraph::new(msg).style(t.tone(Tone::Muted)), screen);
        return;
    }
    let area = Rect {
        x: screen.x + 1,
        width: screen.width - 2,
        ..screen
    };
    let confirming = matches!(app.mode, Mode::Confirm(_));
    let needs_h = if app.current_approval().is_some() || confirming {
        3
    } else {
        0
    };
    let [head, needs, body, foot] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(needs_h),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);

    header(f, head, app, t, now);
    if needs_h > 0 {
        needs_you(f, needs, app, t);
    }
    match app.tab {
        Tab::Overview => overview(f, body, app, t, now),
        Tab::Live => live_tab(f, body, app, t, now),
        Tab::Approvals => approvals_tab(f, body, app, t, now),
        Tab::Permissions => permissions_tab(f, body, app, t, now),
    }
    footer(f, foot, app, t);
    if app.mode == Mode::Help {
        help(f, screen, t);
    }
}

// ---------- Bausteine ----------

fn s(text: impl Into<String>, style: Style) -> Span<'static> {
    Span::styled(text.into(), style)
}

/// Kürzt oder füllt auf genau `width` Zeichen.
fn fit(text: &str, width: usize) -> String {
    let cut = truncate(text, width);
    let n = cut.chars().count();
    format!("{cut}{}", " ".repeat(width.saturating_sub(n)))
}

fn width_of(spans: &[Span]) -> u16 {
    spans.iter().map(|s| s.width()).sum::<usize>() as u16
}

/// Rahmen mit Versalien-Titel links und einer leisen Notiz rechts.
fn panel<'a>(title: &str, note: String, t: &Theme) -> Block<'a> {
    Block::new()
        .borders(Borders::ALL)
        .border_style(t.fg(t.line))
        .title(Line::from(s(format!(" {title} "), t.bold(Tone::Accent))))
        .title(Line::from(s(format!(" {note} "), t.tone(Tone::Muted))).right_aligned())
}

/// `12:39:50` für heute, sonst `11-09 12:39`.
fn when(ts: &str, now: DateTime<Local>) -> String {
    match parse_ts(ts) {
        Some(at) => {
            let at = at.with_timezone(&Local);
            if at.date_naive() == now.date_naive() {
                at.format("%H:%M:%S").to_string()
            } else {
                at.format("%m-%d %H:%M").to_string()
            }
        }
        None => ts.to_owned(),
    }
}

/// Nur die Uhrzeit – für das Band, dessen Datum im Detail steht.
fn clock(ts: &str) -> String {
    parse_ts(ts).map_or_else(
        || ts.to_owned(),
        |at| at.with_timezone(&Local).format("%H:%M:%S").to_string(),
    )
}

fn countdown(secs: u64) -> String {
    format!("{}:{:02}", secs / 60, secs % 60)
}

fn who(client: Option<&str>, session: Option<&str>) -> String {
    match (client, session) {
        (Some(c), Some(s)) => format!("{c}/{s}"),
        (Some(c), None) => c.to_owned(),
        (None, Some(s)) => s.to_owned(),
        (None, None) => "–".to_owned(),
    }
}

// ---------- Kopfzeile ----------

fn header(f: &mut Frame, area: Rect, app: &App, t: &Theme, now: DateTime<Local>) {
    let mut left: Vec<Span> = "HEDGE"
        .chars()
        .zip(t.mark)
        .map(|(c, color)| s(format!("{c} "), t.fg(color).add_modifier(Modifier::BOLD)))
        .collect();
    left.push(s("  ", Style::new()));
    for tab in Tab::ALL {
        let on = tab == app.tab;
        let style = if on {
            t.bold(Tone::Ink).add_modifier(Modifier::UNDERLINED)
        } else {
            t.tone(Tone::Muted)
        };
        left.push(s(tab.title(), style));
        if tab == Tab::Approvals && !app.approvals.is_empty() {
            left.push(s(format!(" {}", app.approvals.len()), t.bold(Tone::Warn)));
        }
        left.push(s("   ", Style::new()));
    }

    // Rechts, nach Wichtigkeit: Verbindung, Kette, „wartet auf dich“, Uhr.
    // Was nicht mehr neben die Reiter passt, entfällt von hinten.
    let link = match &app.link {
        Link::Up => s("● LIVE", t.bold(Tone::Ok)),
        Link::Down(_) => s("○ PROXY OFFLINE", t.bold(Tone::Bad)),
        Link::Unknown => s("○ connecting", t.tone(Tone::Dim)),
    };
    let chain = &app.model.chain;
    let chain = if chain.unchecked {
        s("CHAIN ? no public key", t.tone(Tone::Warn))
    } else if chain.problems.is_empty() {
        s(
            format!("CHAIN ✓ {} records", chain.records),
            t.tone(Tone::Ok),
        )
    } else {
        s(
            format!(" CHAIN ✗ {} problems ", chain.problems.len()),
            t.chip(t.bad),
        )
    };
    let waiting = (!app.approvals.is_empty()).then(|| {
        s(
            format!(" WAITING FOR YOU {} ", app.approvals.len()),
            t.chip(t.warn),
        )
    });
    // Presidio: still, solange alles gut ist; laut, wenn Namen gerade
    // unbemerkt durchgehen.
    let presidio = app
        .status
        .as_ref()
        .and_then(|st| match st["presidio"]["state"].as_str()? {
            "ready" => Some(s("PRESIDIO ●", t.tone(Tone::Ok))),
            "starting" => Some(s("PRESIDIO ◌ starting", t.tone(Tone::Warn))),
            "unavailable" => Some(s(" PRESIDIO ○ DOWN ", t.chip(t.bad))),
            _ => None,
        });
    let clock = s(now.format("%H:%M:%S").to_string(), t.tone(Tone::Muted));
    let room = area.width.saturating_sub(width_of(&left));
    let mut right: Vec<Span> = Vec::new();
    // In Leserichtung: wartet · Verbindung · Kette · Uhr.
    let place = |span: Span<'static>, at_front: bool, right: &mut Vec<Span<'static>>| {
        if width_of(right) + span.width() as u16 + 2 > room {
            return;
        }
        if at_front {
            right.insert(0, s("  ", Style::new()));
            right.insert(0, span);
        } else {
            right.push(span);
            right.push(s("  ", Style::new()));
        }
    };
    place(link, false, &mut right);
    place(chain, false, &mut right);
    if let Some(chip) = waiting {
        place(chip, true, &mut right);
    }
    if let Some(chip) = presidio {
        place(chip, false, &mut right);
    }
    place(clock, false, &mut right);
    right.pop();

    let [row, _] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    let [l, r] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(width_of(&right))]).areas(row);
    f.render_widget(Paragraph::new(Line::from(left)), l);
    f.render_widget(Paragraph::new(Line::from(right)), r);
}

// ---------- „Wartet auf dich“ ----------

fn needs_you(f: &mut Frame, area: Rect, app: &App, t: &Theme) {
    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(t.fg(t.warn))
        .style(Style::new().bg(t.raised));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let (a, confirming) = match (&app.mode, app.current_approval()) {
        (Mode::Confirm(a), _) => (a.as_ref(), true),
        (_, Some(a)) => (a, false),
        _ => return,
    };
    let keys: Vec<Span> = if confirming {
        vec![
            s("y", t.bold(Tone::Ok)),
            s(" yes, run it once   ", t.tone(Tone::Ink)),
            s("any other key", t.bold(Tone::Ink)),
            s(" cancel ", t.tone(Tone::Ink)),
        ]
    } else {
        let more = app.approvals.len().saturating_sub(1);
        let mut k = vec![
            s("a", t.bold(Tone::Ok)),
            s(" approve  ", t.tone(Tone::Ink)),
            s("d", t.bold(Tone::Bad)),
            s(" deny ", t.tone(Tone::Ink)),
        ];
        if more > 0 {
            k.push(s(format!(" +{more} more · 3 "), t.tone(Tone::Muted)));
        }
        k
    };
    let [l, r] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(width_of(&keys))]).areas(inner);

    let chip = if confirming { " APPROVE? " } else { " HOLD " };
    let left = countdown(app.expires_in(a));
    let clock = if a.kind == "chat" {
        format!("expires in {left}")
    } else {
        format!("agent waits · auto-reject in {left}")
    };
    let origin = format!(" · {} · ", who(a.client.as_deref(), a.session.as_deref()));
    let tail = format!("   {clock} · {} · {}", a.rule, a.reason);
    // Der Befehl ist das Wichtigste, die Frist das Zweitwichtigste: Wird es
    // eng, schrumpft zuerst die Begründung, dann erst der Befehl.
    let fixed = chip.chars().count() + 2 + a.tool.chars().count() + origin.chars().count();
    let room = (l.width as usize).saturating_sub(fixed + 1);
    let need = a.preview.chars().count();
    let preview_w = need.min(room.saturating_sub(clock.chars().count() + 3).max(12));
    let line = Line::from(vec![
        s(chip, t.chip(t.warn)),
        s("  ", Style::new()),
        s(a.tool.clone(), t.bold(Tone::Accent)),
        s(origin, t.tone(Tone::Muted)),
        s(truncate(&a.preview, preview_w), t.bold(Tone::Ink)),
        s(
            truncate(&tail, room.saturating_sub(preview_w)),
            t.tone(Tone::Muted),
        ),
    ]);
    f.render_widget(Paragraph::new(line), l);
    f.render_widget(Paragraph::new(Line::from(keys)), r);
}

// ---------- Übersicht ----------

fn overview(f: &mut Frame, area: Rect, app: &App, t: &Theme, now: DateTime<Local>) {
    // Ein entfernter Hedge, von dem (noch) nichts zu lesen ist: sagen, warum.
    if app.remote && app.model.entries.is_empty() {
        let mut text = vec![
            Line::from(""),
            Line::from(s(
                format!("  Watching a remote hedge at {}.", app.base),
                t.tone(Tone::Ink),
            )),
        ];
        match &app.remote_error {
            Some(reason) => {
                text.push(Line::from(s(
                    format!("  Its witness cannot be read: {reason}"),
                    t.tone(Tone::Warn),
                )));
                text.push(Line::from(s(
                    "  Approvals still work from here: press 3.",
                    t.tone(Tone::Muted),
                )));
            }
            None => text.push(Line::from(s(
                "  Reading its witness over the control API …",
                t.tone(Tone::Muted),
            ))),
        }
        f.render_widget(Paragraph::new(text), area);
        return;
    }
    let rows = app.visible_sessions();
    // Tabelle: Rahmen (2) + Kopf (1) + Zeilen + Zähler (3); der Live-Strom
    // behält mindestens ein Drittel.
    let want = rows.len().max(1) as u16 + 6;
    let most = area.height.saturating_sub(area.height / 3).max(8);
    let [top, bottom] =
        Layout::vertical([Constraint::Length(want.min(most)), Constraint::Min(0)]).areas(area);

    let active = rows.iter().filter(|r| is_active(r, now)).count();
    let block = panel(
        "SESSIONS",
        format!("{} sessions · {active} active", rows.len()),
        t,
    );
    let inner = block.inner(top);
    f.render_widget(block, top);
    let [table_area, stats_area] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).areas(inner);

    if rows.is_empty() {
        let text = if app.model.sessions.is_empty() {
            format!(
                " nothing recorded yet – start `hedge run` and point your agent at {}",
                app.base
            )
        } else {
            " no session matches the filter – esc clears it".to_owned()
        };
        f.render_widget(Paragraph::new(text).style(t.tone(Tone::Muted)), table_area);
    } else {
        sessions_table(f, table_area, app, t, &rows, now);
    }
    stats(f, stats_area, app, t, now);

    let filter = Filter {
        session: None,
        ..app.filter()
    };
    let note = if app.tape == TapeFilter::Alerts {
        "alerts only · newest first"
    } else {
        "newest first"
    };
    let block = panel("LIVE", note.to_owned(), t);
    let inner = block.inner(bottom);
    f.render_widget(block, bottom);
    let lines: Vec<Line> = app
        .model
        .entries
        .iter()
        .rev()
        .filter(|e| filter.wants(e))
        .take(inner.height as usize)
        .map(|e| entry_line(e, app, t, inner.width as usize, now))
        .collect();
    if lines.is_empty() {
        f.render_widget(
            Paragraph::new(" waiting for the first request…").style(t.tone(Tone::Dim)),
            inner,
        );
    } else {
        f.render_widget(Paragraph::new(lines), inner);
    }
}

fn is_active(r: &SessionRow, now: DateTime<Local>) -> bool {
    parse_ts(&r.last).is_some_and(|at| (now.to_utc() - at).num_seconds() < ACTIVE_SECS)
}

struct Column {
    title: &'static str,
    width: u16,
    right: bool,
    /// Reihenfolge, in der Spalten weichen, wenn das Terminal zu schmal ist:
    /// 1 zuerst, 0 nie.
    drop: u8,
}

const fn col(title: &'static str, width: u16, right: bool, drop: u8) -> Column {
    Column {
        title,
        width,
        right,
        drop,
    }
}

const COLUMNS: [Column; 13] = [
    col("SESSION", 10, false, 0),
    col("CLIENT", 14, false, 2),
    col("MODEL", 18, false, 1),
    col("STARTED", 11, false, 3),
    col("STATE", 8, false, 6),
    col("REQS", 5, true, 0),
    col("TOOLS", 5, true, 5),
    col("BLOCKED", 7, true, 0),
    col("HELD", 5, true, 0),
    col("FLAGGED", 7, true, 0),
    col("FINDINGS", 8, true, 0),
    col("TOKENS", 8, true, 4),
    col("WITNESS", 9, false, 0),
];
const COLUMN_GAP: u16 = 2;

/// Die Spalten, die in `width` passen. Die Zahlen und der Zustand der
/// Kette bleiben immer; Modell, Client, Start, Tokens weichen zuerst.
fn columns_for(width: u16, clients: bool) -> Vec<usize> {
    let mut shown: Vec<usize> = (0..COLUMNS.len())
        .filter(|i| clients || COLUMNS[*i].title != "CLIENT")
        .collect();
    let needed = |shown: &[usize]| -> u16 {
        let cells: u16 = shown.iter().map(|i| COLUMNS[*i].width).sum();
        // +1 für die Auswahlmarke am Zeilenanfang.
        cells + COLUMN_GAP * shown.len().saturating_sub(1) as u16 + 1
    };
    while needed(&shown) > width {
        let next = shown
            .iter()
            .filter(|i| COLUMNS[**i].drop > 0)
            .min_by_key(|i| COLUMNS[**i].drop)
            .copied();
        match next {
            Some(i) => shown.retain(|x| *x != i),
            None => break,
        }
    }
    shown
}

fn sessions_table(
    f: &mut Frame,
    area: Rect,
    app: &App,
    t: &Theme,
    rows: &[&SessionRow],
    now: DateTime<Local>,
) {
    // Ohne Central-Mode hat keine Session einen Client: Spalte weglassen.
    let clients = rows.iter().any(|r| r.client.is_some());
    let shown = columns_for(area.width, clients);
    // Zahl: 0 tritt zurück, alles andere trägt die Farbe seiner Bedeutung.
    let num = |n: usize, tone: Tone| -> Span<'static> {
        if n == 0 {
            s("0", t.tone(Tone::Dim))
        } else {
            s(n.to_string(), t.bold(tone))
        }
    };
    let cells = |r: &SessionRow| -> [Span<'static>; 13] {
        let id = if r.id == NO_SESSION {
            s("(none)", t.tone(Tone::Dim))
        } else {
            s(r.id.clone(), t.tone(Tone::Ink))
        };
        let state = if is_active(r, now) {
            s("● active", t.tone(Tone::Ok))
        } else {
            s("○ idle", t.tone(Tone::Dim))
        };
        let waiting = app
            .approvals
            .iter()
            .any(|a| a.session.as_deref() == Some(r.id.as_str()));
        let witness = if waiting {
            s(" HOLD ", t.chip(t.warn))
        } else if r.broken {
            s("✗ broken", t.bold(Tone::Bad))
        } else if app.model.chain.unchecked {
            s("? unknown", t.tone(Tone::Warn))
        } else {
            s("✓ chain", t.tone(Tone::Ok))
        };
        [
            id,
            s(
                r.client.clone().unwrap_or_else(|| "–".into()),
                t.tone(Tone::Muted),
            ),
            s(r.models.join(", "), t.tone(Tone::Accent)),
            s(when(&r.first, now), t.tone(Tone::Muted)),
            state,
            s(r.requests.to_string(), t.tone(Tone::Ink)),
            s(r.tools.to_string(), t.tone(Tone::Ink)),
            num(r.blocked, Tone::Bad),
            num(r.held, Tone::Warn),
            num(r.flagged, Tone::Warn),
            num(r.findings, Tone::Accent),
            s(human_count(r.tokens), t.tone(Tone::Muted)),
            witness,
        ]
    };
    let aligned = |span: Span<'static>, i: usize| -> Cell<'static> {
        let line = Line::from(span);
        Cell::from(if COLUMNS[i].right {
            line.right_aligned()
        } else {
            line
        })
    };
    let header = Row::new(
        shown
            .iter()
            .map(|i| aligned(s(COLUMNS[*i].title, t.tone(Tone::Muted)), *i)),
    );
    // Die Auswahl färbt die Zeile selbst ein (nicht als Überlagerung): so
    // behält eine gefüllte Fläche wie HOLD ihre eigene Farbe.
    let at = app.selected_index();
    let body = rows.iter().enumerate().map(|(n, r)| {
        let all = cells(r);
        let row = Row::new(shown.iter().map(|i| aligned(all[*i].clone(), *i)));
        if n == at {
            row.style(t.selected())
        } else {
            row
        }
    });
    // Das Modell bekommt den Platz, der übrig bleibt.
    let widths = shown.iter().map(|i| match COLUMNS[*i].title {
        "MODEL" => Constraint::Min(COLUMNS[*i].width),
        _ => Constraint::Length(COLUMNS[*i].width),
    });
    let table = Table::new(body, widths)
        .header(header)
        .column_spacing(COLUMN_GAP)
        .highlight_symbol(Line::from(s("▌", t.bold(Tone::Accent))))
        .style(t.tone(Tone::Ink));
    let mut state = TableState::new().with_selected(Some(at));
    f.render_stateful_widget(table, area, &mut state);
}

fn stats(f: &mut Frame, area: Rect, app: &App, t: &Theme, now: DateTime<Local>) {
    let m = &app.model;
    // Sechs Zellen; auf schmalen Terminals rücken sie zusammen.
    let cell = (area.width.saturating_sub(1) as usize / 6).clamp(8, 16);
    let big = |n: usize, tone: Tone| -> Span<'static> {
        let tone = if n == 0 { Tone::Dim } else { tone };
        s(fit(&n.to_string(), cell), t.bold(tone))
    };
    let labels = [
        "REQUESTS",
        "BLOCKED",
        "HELD",
        "FLAGGED",
        "NEW FINDINGS",
        "TOKENS TODAY",
    ];
    let label_line = Line::from(
        std::iter::once(s(" ", Style::new()))
            .chain(labels.iter().map(|l| s(fit(l, cell), t.tone(Tone::Muted))))
            .collect::<Vec<_>>(),
    );
    let values = Line::from(vec![
        s(" ", Style::new()),
        s(fit(&m.totals.requests.to_string(), cell), t.bold(Tone::Ink)),
        big(m.totals.blocked, Tone::Bad),
        big(m.totals.held, Tone::Warn),
        big(m.totals.flagged, Tone::Warn),
        big(m.totals.findings, Tone::Accent),
        s(
            human_count(m.tokens_on(now.date_naive())),
            t.bold(Tone::Ink),
        ),
    ]);
    f.render_widget(
        Paragraph::new(vec![Line::from(""), label_line, values]),
        area,
    );
}

// ---------- Einträge ----------

/// Ein Eintrag in einer Zeile: Zeit, Session, Urteil, Gegenstand, Detail, Regel.
fn entry_line(
    e: &Entry,
    app: &App,
    t: &Theme,
    width: usize,
    now: DateTime<Local>,
) -> Line<'static> {
    let Summary {
        label,
        tone,
        loud,
        subject,
        detail,
        rule,
    } = summary(e);
    // Die gefüllte Fläche gehört dem, was jetzt auf einen Menschen wartet.
    // Ein Aufruf, über den schon entschieden ist, war nur „held“.
    let verdict = if label == "HOLD" {
        if still_waiting(e, app) {
            s(" HOLD ", t.chip(t.warn))
        } else {
            s(fit("held", 6), t.tone(Tone::Warn))
        }
    } else if loud {
        s(fit(label, 6), t.bold(tone))
    } else {
        s(fit(label, 6), t.tone(tone))
    };
    let session = match &e.session {
        Some(id) => s(fit(id, 8), t.tone(Tone::Ink)),
        None => s(fit("–", 8), t.tone(Tone::Dim)),
    };
    let time = when(&e.ts, now);
    // Feste Spalten: Zeit, Session, Urteil, Gegenstand – der Rest teilt sich
    // Detail und Regel.
    // Schmal: Gegenstand kürzer, die Regel höchstens ein Drittel.
    let (subject_w, rule_share) = if width >= 110 { (20, 2) } else { (12, 3) };
    let fixed = 1 + time.chars().count() + 2 + 8 + 2 + 6 + 2 + subject_w + 2;
    let rest = width.saturating_sub(fixed);
    let rule_w = rule.chars().count().min(rest / rule_share).min(44);
    let detail_w = rest.saturating_sub(rule_w + 2);
    let detail_tone = if matches!(tone, Tone::Ok | Tone::Dim) {
        Tone::Muted
    } else {
        Tone::Ink
    };
    Line::from(vec![
        s(format!(" {time}  "), t.tone(Tone::Muted)),
        session,
        s("  ", Style::new()),
        verdict,
        s("  ", Style::new()),
        s(fit(&subject, subject_w), t.tone(Tone::Accent)),
        s("  ", Style::new()),
        s(fit(&detail, detail_w), t.tone(detail_tone)),
        s("  ", Style::new()),
        s(truncate(&rule, rule_w), t.tone(Tone::Muted)),
    ])
}

/// Wartet die Freigabe zu diesem Eintrag noch? Bei einem Ereignis steht die
/// ID vorn im Detail, bei einer Anfrage am Tool-Aufruf.
fn still_waiting(e: &Entry, app: &App) -> bool {
    let open = |id: &str| app.approvals.iter().any(|a| a.id == id);
    let from_event = e
        .detail
        .as_deref()
        .filter(|_| e.event.is_some())
        .and_then(|d| d.split_whitespace().next());
    from_event.is_some_and(open)
        || e.tools
            .iter()
            .filter(|t| t.decision == "held")
            .filter_map(|t| t.approval.as_deref())
            .any(open)
}

/// Bricht Text an Leerzeichen auf `width` Zeichen um; überlange Wörter
/// werden hart getrennt. Liefert höchstens `max` Zeilen, die letzte mit `…`.
fn wrap(text: &str, width: usize, max: usize) -> Vec<String> {
    let width = width.max(8);
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let mut word = word.to_owned();
        loop {
            let used = line.chars().count();
            let need = word.chars().count() + usize::from(used > 0);
            if used + need <= width {
                if used > 0 {
                    line.push(' ');
                }
                line.push_str(&word);
                break;
            }
            if used > 0 {
                lines.push(std::mem::take(&mut line));
                continue;
            }
            let head: String = word.chars().take(width).collect();
            word = word.chars().skip(width).collect();
            lines.push(head);
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    if lines.len() > max {
        lines.truncate(max);
        if let Some(last) = lines.last_mut() {
            *last = truncate(&format!("{last} …"), width);
        }
    }
    lines
}

/// Eine Schaltfläche in einer Reihe: die gewählte gefüllt, die anderen leise.
fn choice(label: String, on: bool, t: &Theme) -> Span<'static> {
    if on {
        s(format!(" {label} "), t.chip(t.accent))
    } else {
        s(format!(" {label} "), t.tone(Tone::Muted))
    }
}

/// Färbt eine Zeile bis zum rechten Rand als Auswahl ein.
fn select(mut line: Line<'static>, width: u16, t: &Theme) -> Line<'static> {
    let gap = (width as usize).saturating_sub(line.width());
    line.push_span(s(" ".repeat(gap), Style::new()));
    line.style(t.selected())
}

fn fate_span(fate: Fate, t: &Theme) -> Span<'static> {
    match fate {
        Fate::Waiting => s(" WAITING ", t.chip(t.warn)),
        Fate::Blocked => s("BLOCKED", t.bold(Tone::Bad)),
        Fate::Flagged => s("RAN · FLAGGED", t.tone(Tone::Warn)),
        Fate::Masked => s("MASKED · SENT", t.tone(Tone::Accent)),
        Fate::Approved { ran: true } => s("APPROVED · RAN", t.tone(Tone::Ok)),
        Fate::Approved { ran: false } => s("APPROVED", t.tone(Tone::Ok)),
        Fate::Rejected => s("REJECTED", t.bold(Tone::Bad)),
        Fate::Expired => s("EXPIRED", t.tone(Tone::Bad)),
        Fate::Unanswered => s("UNANSWERED", t.tone(Tone::Dim)),
    }
}

fn ruling_tone(r: Ruling) -> Tone {
    match r {
        Ruling::Hold | Ruling::Flag => Tone::Warn,
        Ruling::Deny | Ruling::Block => Tone::Bad,
        Ruling::Redact => Tone::Accent,
    }
}

/// `HEDGE-SHELL-003 force push rewrites remote history`
fn rule_words(rule: &str, app: &App) -> String {
    match app.rule_text(rule) {
        Some(words) => format!("{rule} {words}"),
        None => rule.to_owned(),
    }
}

// ---------- Live: Sessions, Band, Detail ----------

fn live_tab(f: &mut Frame, area: Rect, app: &App, t: &Theme, now: DateTime<Local>) {
    let focus = app.focus.as_deref().and_then(|id| app.model.session(id));
    let [top, main] = Layout::vertical([
        Constraint::Length(if focus.is_some() { 3 } else { 0 }),
        Constraint::Min(0),
    ])
    .areas(area);
    if let Some(r) = focus {
        session_head(f, top, app, t, r, now);
    }
    // Schmal weicht erst die Session-Liste, dann das Detail; das Band bleibt.
    let left = if area.width >= 124 { 27 } else { 0 };
    let right = if area.width >= 100 { 42 } else { 0 };
    let [l, c, r] = Layout::horizontal([
        Constraint::Length(left),
        Constraint::Min(40),
        Constraint::Length(right),
    ])
    .areas(main);

    let scope: Vec<&Entry> = app
        .model
        .entries
        .iter()
        .filter(|e| e.event.is_none())
        .filter(|e| app.focus.as_deref().is_none_or(|id| session_key(e) == id))
        .collect();
    if left > 0 {
        let mut mix: Vec<(&str, usize)> = Vec::new();
        for name in scope.iter().flat_map(|e| &e.tools).map(|x| x.name.as_str()) {
            match mix.iter_mut().find(|(n, _)| *n == name) {
                Some((_, count)) => *count += 1,
                None => mix.push((name, 1)),
            }
        }
        mix.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        let mix_h = (mix.len() as u16 + 2).clamp(3, 9);
        let [list, tools] =
            Layout::vertical([Constraint::Min(4), Constraint::Length(mix_h)]).areas(l);
        session_list(f, list, app, t, now);
        tool_mix(f, tools, t, &mix);
    }
    let picked = app.rows().nth(app.cursor);
    tape(f, c, app, t);
    if right > 0 {
        let [detail, policy] =
            Layout::vertical([Constraint::Min(6), Constraint::Length(8)]).areas(r);
        record_detail(f, detail, app, t, picked.as_ref(), now);
        policy_box(f, policy, app, t, &scope);
    }
}

/// Kopf einer geöffneten Session: wer, wann, was kam dabei heraus – und der
/// Befehl, der sie als Beweis exportiert.
fn session_head(
    f: &mut Frame,
    area: Rect,
    app: &App,
    t: &Theme,
    r: &SessionRow,
    now: DateTime<Local>,
) {
    let dot = s(" · ", t.tone(Tone::Dim));
    let duration = match (parse_ts(&r.first), parse_ts(&r.last)) {
        (Some(a), Some(b)) => human_duration((b - a).num_milliseconds().max(0) as u64),
        _ => "–".to_owned(),
    };
    let name = if r.id == NO_SESSION {
        "(no session)"
    } else {
        &r.id
    };
    let who = Line::from(vec![
        s(" ← esc  ", t.tone(Tone::Dim)),
        s(name.to_owned(), t.bold(Tone::Ink)),
        s("  ", Style::new()),
        s(
            r.client.clone().unwrap_or_else(|| "local".into()),
            t.tone(Tone::Muted),
        ),
        dot.clone(),
        s(r.models.join(", "), t.tone(Tone::Accent)),
        dot.clone(),
        s(
            format!(
                "{} → {} ({duration})",
                when(&r.first, now),
                when(&r.last, now)
            ),
            t.tone(Tone::Muted),
        ),
    ]);
    let part = |n: usize, word: &str, tone: Tone| -> Span<'static> {
        let tone = if n == 0 { Tone::Dim } else { tone };
        s(format!("{n} {word}"), t.tone(tone))
    };
    let chain = if r.broken {
        s("✗ CHAIN BROKEN", t.bold(Tone::Bad))
    } else if app.model.chain.unchecked {
        s("? not verified", t.tone(Tone::Warn))
    } else {
        s("✓ VERIFIED", t.bold(Tone::Ok))
    };
    let facts = Line::from(vec![
        s("        ", Style::new()),
        chain,
        dot.clone(),
        s(format!("{} requests", r.requests), t.tone(Tone::Ink)),
        dot.clone(),
        s(format!("{} tool calls", r.tools), t.tone(Tone::Ink)),
        dot.clone(),
        part(r.blocked, "blocked", Tone::Bad),
        dot.clone(),
        part(r.held, "held", Tone::Warn),
        dot.clone(),
        part(r.flagged, "flagged", Tone::Warn),
        dot.clone(),
        part(r.findings, "findings", Tone::Accent),
        dot,
        s(
            format!("{} tokens", human_count(r.tokens)),
            t.tone(Tone::Muted),
        ),
    ]);
    let export = vec![
        s("EXPORT ", t.tone(Tone::Muted)),
        s(
            format!("hedge export --session {} -o run.json ", r.id),
            t.tone(Tone::Ink),
        ),
    ];
    let verify = vec![
        s("VERIFY ", t.tone(Tone::Muted)),
        s("hedge verify --bundle run.json ", t.tone(Tone::Ink)),
    ];
    let [row1, row2, _] = Layout::vertical([Constraint::Length(1); 3]).areas(area);
    for (row, left, right) in [(row1, who, export), (row2, facts, verify)] {
        // Die Befehle stehen rechts, wenn links Platz bleibt.
        let need = left.width() as u16 + width_of(&right) + 2;
        let w = if need <= row.width {
            width_of(&right)
        } else {
            0
        };
        let [a, b] = Layout::horizontal([Constraint::Min(0), Constraint::Length(w)]).areas(row);
        f.render_widget(Paragraph::new(left), a);
        f.render_widget(Paragraph::new(Line::from(right)), b);
    }
}

fn session_list(f: &mut Frame, area: Rect, app: &App, t: &Theme, now: DateTime<Local>) {
    let block = panel("SESSIONS", "← →".to_owned(), t);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let width = inner.width;
    let mark = |on: bool| {
        if on {
            s("▌", t.bold(Tone::Accent))
        } else {
            s(" ", Style::new())
        }
    };
    let paint = |line: Line<'static>, on: bool| if on { select(line, width, t) } else { line };

    let all = app.focus.is_none();
    let mut lines = vec![
        paint(
            Line::from(vec![
                mark(all),
                s("all sessions", t.bold(Tone::Ink)),
                s(
                    format!("  {}", app.model.sessions.len()),
                    t.tone(Tone::Muted),
                ),
            ]),
            all,
        ),
        Line::from(""),
    ];
    // Die gewählte Session bleibt sichtbar: Liste ab ihr, wenn sie sonst
    // unter dem Rand läge (jede Session belegt drei Zeilen).
    let fit_n = (inner.height.saturating_sub(2) / 3).max(1) as usize;
    let at = app
        .focus
        .as_ref()
        .and_then(|id| app.model.sessions.iter().position(|r| &r.id == id))
        .unwrap_or(0);
    let first = at.saturating_sub(fit_n - 1);
    for r in app.model.sessions.iter().skip(first).take(fit_n) {
        let on = app.focus.as_deref() == Some(r.id.as_str());
        let waiting = app
            .approvals
            .iter()
            .any(|a| a.session.as_deref() == Some(r.id.as_str()));
        let state = if waiting {
            s(" HOLD ", t.chip(t.warn))
        } else if is_active(r, now) {
            s("● active", t.tone(Tone::Ok))
        } else {
            s("○ idle", t.tone(Tone::Dim))
        };
        let name = if r.id == NO_SESSION { "(none)" } else { &r.id };
        lines.push(paint(
            Line::from(vec![mark(on), s(fit(name, 12), t.bold(Tone::Ink)), state]),
            on,
        ));
        let mut marks: Vec<Span> = Vec::new();
        for (n, word, tone) in [
            (r.blocked, "blocked", Tone::Bad),
            (r.held, "held", Tone::Warn),
            (r.flagged, "flagged", Tone::Warn),
            (r.findings, "found", Tone::Accent),
        ] {
            if n > 0 {
                marks.push(s(format!("{n} {word} "), t.tone(tone)));
            }
        }
        if marks.is_empty() {
            marks.push(s("nothing stopped", t.tone(Tone::Dim)));
        }
        lines.push(paint(
            Line::from(vec![
                mark(on),
                s(
                    format!("{} requests · {} calls", r.requests, r.tools),
                    t.tone(Tone::Muted),
                ),
            ]),
            on,
        ));
        marks.insert(0, mark(on));
        lines.push(paint(Line::from(marks), on));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn tool_mix(f: &mut Frame, area: Rect, t: &Theme, mix: &[(&str, usize)]) {
    let block = panel("TOOL MIX", format!("{} tools", mix.len()), t);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let most = mix.first().map_or(1, |(_, n)| *n).max(1);
    let bar_w = (inner.width as usize).saturating_sub(12 + 5);
    let lines: Vec<Line> = mix
        .iter()
        .map(|(name, n)| {
            let filled = (n * bar_w).div_ceil(most).min(bar_w);
            Line::from(vec![
                s(format!(" {}", fit(name, 11)), t.tone(Tone::Ink)),
                s("█".repeat(filled), t.tone(Tone::Accent)),
                s("░".repeat(bar_w - filled), t.fg(t.line)),
                s(format!("{n:>4}"), t.tone(Tone::Muted)),
            ])
        })
        .collect();
    if lines.is_empty() {
        f.render_widget(
            Paragraph::new(" no tool calls yet").style(t.tone(Tone::Dim)),
            inner,
        );
    } else {
        f.render_widget(Paragraph::new(lines), inner);
    }
}

fn tape(f: &mut Frame, area: Rect, app: &App, t: &Theme) {
    let mut title = vec![s(" TAPE ", t.bold(Tone::Accent))];
    for filter in TapeFilter::ALL {
        title.push(choice(filter.title().to_owned(), filter == app.tape, t));
    }
    let mut note = String::new();
    if !app.query.is_empty() {
        note.push_str(&format!("filter: {} · ", app.query));
    }
    note.push_str("newest first");
    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(t.fg(t.line))
        .title(Line::from(title))
        .title(Line::from(s(format!(" {note} "), t.tone(Tone::Muted))).right_aligned());
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [head, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);

    let with_session = app.focus.is_none();
    let width = inner.width as usize;
    // Zeit, [Session], Ereignis, Tool – dann Text; rechts Status und Dauer.
    let lead = 1 + 8 + 2 + if with_session { 10 } else { 0 } + 7 + 10;
    // Die Dauer weicht zuerst: Der Text ist wichtiger.
    let (status_w, ms_w) = if width >= 110 { (14, 7) } else { (14, 0) };
    let text_w = width.saturating_sub(lead + status_w + ms_w + 2);

    let mut titles = vec![s(format!(" {}  ", fit("TIME", 8)), t.tone(Tone::Muted))];
    if with_session {
        titles.push(s(fit("SESSION", 10), t.tone(Tone::Muted)));
    }
    titles.push(s(
        format!(
            "{}{}{}  {}",
            fit("EVT", 7),
            fit("TOOL", 10),
            fit("TARGET / TEXT", text_w),
            fit("STATUS", status_w)
        ),
        t.tone(Tone::Muted),
    ));
    if ms_w > 0 {
        titles.push(s(format!("{:>ms_w$}", "TIME"), t.tone(Tone::Muted)));
    }
    f.render_widget(Paragraph::new(Line::from(titles)), head);

    let height = body.height as usize;
    let first = app.cursor.saturating_sub(height.saturating_sub(1));
    let lines: Vec<Line> = app
        .rows()
        .enumerate()
        .skip(first)
        .take(height)
        .map(|(i, (e, r))| {
            let on = i == app.cursor;
            let child = !matches!(r.evt, "MODEL" | "BLOCK") && e.event.is_none();
            let mut spans = vec![
                if on {
                    s("▌", t.bold(Tone::Accent))
                } else {
                    s(" ", Style::new())
                },
                // Unterzeilen einer Anfrage wiederholen die Zeit nicht.
                s(
                    format!(
                        "{}  ",
                        fit(&if child { String::new() } else { clock(&e.ts) }, 8)
                    ),
                    t.tone(Tone::Muted),
                ),
            ];
            if with_session {
                let id = if child {
                    ""
                } else {
                    e.session.as_deref().unwrap_or("–")
                };
                spans.push(s(fit(id, 10), t.tone(Tone::Ink)));
            }
            spans.push(if r.evt == "HOLD" && r.status == "WAITING" {
                s(" HOLD  ", t.chip(t.warn))
            } else if r.decision || r.approval {
                s(fit(r.evt, 7), t.bold(r.tone))
            } else {
                s(fit(r.evt, 7), t.tone(r.tone))
            });
            spans.push(s(fit(&r.tool, 10), t.tone(Tone::Ink)));
            let text_tone = match r.evt {
                "MODEL" | "TOOL" | "START" | "STOP" | "NOTE" | "EVENT" => Tone::Muted,
                "FIND" => r.tone,
                _ => Tone::Ink,
            };
            spans.push(s(fit(&r.text, text_w), t.tone(text_tone)));
            spans.push(s("  ", Style::new()));
            spans.push(s(fit(&r.status, status_w), t.tone(r.status_tone)));
            if ms_w > 0 {
                let ms = r.ms.map(human_duration).unwrap_or_default();
                spans.push(s(format!("{ms:>ms_w$}"), t.tone(Tone::Dim)));
            }
            let line = Line::from(spans);
            if on {
                select(line, inner.width, t)
            } else {
                line
            }
        })
        .collect();
    if lines.is_empty() {
        let text = if app.model.entries.is_empty() {
            " waiting for the first request…"
        } else {
            " nothing matches – f changes the filter, esc clears the search"
        };
        f.render_widget(Paragraph::new(text).style(t.tone(Tone::Dim)), body);
    } else {
        f.render_widget(Paragraph::new(lines), body);
    }
}

/// Alles zum ausgewählten Eintrag: die Anfrage, und – steht die Auswahl auf
/// einem Tool-Aufruf – was Hedge damit gemacht hat und warum.
fn record_detail(
    f: &mut Frame,
    area: Rect,
    app: &App,
    t: &Theme,
    picked: Option<&(&Entry, TapeRow)>,
    now: DateTime<Local>,
) {
    let note = picked.map_or(String::new(), |(e, _)| format!("record #{}", e.seq));
    let block = panel("DETAIL", note, t);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let Some((e, row)) = picked else {
        f.render_widget(
            Paragraph::new(" select a row with ↑ ↓").style(t.tone(Tone::Dim)),
            inner,
        );
        return;
    };
    let room = (inner.width as usize).saturating_sub(12);
    let mut lines: Vec<Line> = Vec::new();
    // Schlüssel links, Wert rechts; lange Werte brechen eingerückt um.
    let mut put = |key: &str, value: &str, tone: Tone, max: usize| {
        // Ohne Schlüssel und Wert: eine Leerzeile als Absatz.
        if key.is_empty() && value.is_empty() {
            lines.push(Line::from(""));
            return;
        }
        for (i, part) in wrap(value, room, max).into_iter().enumerate() {
            lines.push(Line::from(vec![
                s(
                    format!(" {}", fit(if i == 0 { key } else { "" }, 11)),
                    t.tone(Tone::Muted),
                ),
                s(part, t.tone(tone)),
            ]));
        }
    };
    let at = parse_ts(&e.ts).map_or(e.ts.clone(), |x| {
        x.with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    });
    put("WHEN", &at, Tone::Ink, 1);
    put(
        "SESSION",
        &who(e.client.as_deref(), e.session.as_deref()),
        Tone::Ink,
        1,
    );
    if let Some(event) = &e.event {
        put("EVENT", event, Tone::Accent, 1);
        put("DETAIL", e.detail.as_deref().unwrap_or("–"), Tone::Ink, 6);
    } else {
        put("MODEL", e.model.as_deref().unwrap_or("–"), Tone::Accent, 1);
        put(
            "UPSTREAM",
            &format!("{} {} {}", e.upstream, e.method, e.path),
            Tone::Muted,
            2,
        );
        let (action, tone) = match e.action.as_str() {
            "block" => ("blocked – never reached the model", Tone::Bad),
            "redact" => ("forwarded with findings masked", Tone::Accent),
            _ => ("forwarded unchanged", Tone::Ok),
        };
        put("PROMPT", action, tone, 2);
        let status = match (e.status, &e.stop_reason) {
            (Some(code), Some(stop)) => format!("{code} · {stop}"),
            (Some(code), None) => code.to_string(),
            (None, _) => "no answer".to_owned(),
        };
        put(
            "ANSWER",
            &format!("{status} · {}", human_duration(e.duration_ms)),
            Tone::Ink,
            1,
        );
        if e.tokens_in.is_some() || e.tokens_out.is_some() {
            put(
                "TOKENS",
                &format!(
                    "{} in · {} out · {} cached",
                    human_count(e.tokens_in.unwrap_or(0)),
                    human_count(e.tokens_out.unwrap_or(0)),
                    human_count(e.tokens_cached.unwrap_or(0))
                ),
                Tone::Ink,
                1,
            );
        }
        if let Some(why) = &e.detail {
            put("WHY", why, Tone::Ink, 3);
        }
    }

    // Der Tool-Aufruf unter der Auswahl.
    let call = e.tools.iter().find(|x| {
        !row.tool.is_empty()
            && x.name == row.tool
            && row.text.starts_with(x.preview.as_deref().unwrap_or(""))
    });
    if let Some(call) = call.filter(|_| e.event.is_none()) {
        put("", "", Tone::Ink, 1);
        put("CALL", &call.name, Tone::Accent, 1);
        put(
            "INPUT",
            call.preview.as_deref().unwrap_or("–"),
            Tone::Ink,
            4,
        );
        if let Some(rule) = &call.rule {
            put("RULE", &rule_words(rule, app), Tone::Ink, 3);
        }
        put("OUTCOME", &row.status, row.status_tone, 1);
        if let Some(id) = &call.approval {
            let answer = match app.model.answer(id) {
                Some(a) if a.via.is_empty() => {
                    format!("{id} · nobody answered · {}", when(&a.ts, now))
                }
                Some(a) => format!("{id} · via {} · {}", a.via, when(&a.ts, now)),
                None if app.is_open(id) => format!("{id} · a approve · d deny"),
                None => id.clone(),
            };
            put("APPROVAL", &answer, Tone::Ink, 2);
        }
        put("INPUT SHA", &call.input_sha256, Tone::Dim, 1);
    } else if e.event.is_none() {
        let all: Vec<&crate::witness::FindingRecord> =
            e.findings.iter().chain(&e.response_findings).collect();
        if !all.is_empty() {
            put("", "", Tone::Ink, 1);
        }
        for (i, finding) in all.iter().take(6).enumerate() {
            let hint = finding.hint.as_deref().unwrap_or("");
            let text = format!(
                "{} {hint} · {}{}",
                crate::detect::describe_kind(&finding.kind),
                finding.path,
                if finding.repeat {
                    " · seen before"
                } else {
                    ""
                }
            );
            let tone = if finding.repeat { Tone::Dim } else { Tone::Ink };
            put(if i == 0 { "FINDINGS" } else { "" }, &text, tone, 2);
        }
        if all.len() > 6 {
            put("", &format!("+{} more", all.len() - 6), Tone::Dim, 1);
        }
    }

    put("", "", Tone::Ink, 1);
    put("HASH", &e.hash, Tone::Dim, 1);
    put("SIGNED BY", &e.key_id, Tone::Dim, 1);
    f.render_widget(Paragraph::new(lines), inner);
}

fn policy_box(f: &mut Frame, area: Rect, app: &App, t: &Theme, scope: &[&Entry]) {
    let note = if app.focus.is_some() {
        "this session"
    } else {
        "all sessions"
    };
    let block = panel("POLICY", note.to_owned(), t);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let tools = || scope.iter().flat_map(|e| &e.tools);
    let hit = |x: &&crate::witness::ToolRecord| x.rule.is_some() && x.decision != "allow";
    let counts = [
        ("ALLOWED", tools().filter(|x| !hit(x)).count(), Tone::Ok),
        (
            "FLAGGED",
            tools().filter(|x| x.decision == "flag").count(),
            Tone::Warn,
        ),
        (
            "DENIED",
            tools().filter(|x| x.decision == "deny").count(),
            Tone::Bad,
        ),
        (
            "HELD",
            tools()
                .filter(|x| x.approval.is_some() && x.decision != "approved")
                .count(),
            Tone::Warn,
        ),
        (
            "MASKED",
            scope
                .iter()
                .filter(|e| e.action == "redact" && e.findings.iter().any(|x| !x.repeat))
                .count(),
            Tone::Accent,
        ),
        (
            "BLOCKED",
            scope.iter().filter(|e| e.action == "block").count(),
            Tone::Bad,
        ),
    ];
    let lines: Vec<Line> = counts
        .iter()
        .map(|(label, n, tone)| {
            Line::from(vec![
                s(format!(" {}", fit(label, 11)), t.tone(Tone::Muted)),
                s(
                    n.to_string(),
                    if *n == 0 {
                        t.tone(Tone::Dim)
                    } else {
                        t.bold(*tone)
                    },
                ),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

// ---------- Freigaben ----------

const CARD_HEIGHT: u16 = 10;

fn approvals_tab(f: &mut Frame, area: Rect, app: &App, t: &Theme, now: DateTime<Local>) {
    let block = panel(
        "APPROVALS",
        format!(
            "{} waiting · {} answered",
            app.approvals.len(),
            app.model.answers.len()
        ),
        t,
    );
    let inner = block.inner(area);
    f.render_widget(block, area);

    let intro = "Calls hedge is holding until a person answers. An answer binds to the exact call, is signed into the witness and works once. Answer right here: a approve · d deny.";
    let intro = wrap(intro, (inner.width as usize).saturating_sub(2), 3);
    // Karten für so viele Anfragen, wie Platz ist; die Historie behält ein Drittel.
    let most = inner.height.saturating_sub(intro.len() as u16 + 2) * 2 / 3;
    let shown = ((most / CARD_HEIGHT).max(1) as usize).min(app.approvals.len().max(1));
    let cards_h = if app.approvals.is_empty() {
        2
    } else {
        shown as u16 * CARD_HEIGHT
    };
    let [text, cards, answered] = Layout::vertical([
        Constraint::Length(intro.len() as u16 + 2),
        Constraint::Length(cards_h),
        Constraint::Min(0),
    ])
    .areas(inner);

    let mut lines = vec![Line::from("")];
    lines.extend(
        intro
            .into_iter()
            .map(|x| Line::from(s(format!(" {x}"), t.tone(Tone::Muted)))),
    );
    f.render_widget(Paragraph::new(lines), text);

    if app.approvals.is_empty() {
        let line = match &app.link {
            Link::Down(reason) => Line::from(vec![
                s(" ✗ ", t.bold(Tone::Bad)),
                s(reason.clone(), t.tone(Tone::Ink)),
            ]),
            Link::Unknown => Line::from(s(" asking hedge…", t.tone(Tone::Dim))),
            Link::Up => Line::from(vec![
                s(" ✓ ", t.tone(Tone::Ok)),
                s("nothing is waiting for approval", t.tone(Tone::Ink)),
            ]),
        };
        f.render_widget(Paragraph::new(line), cards);
    } else {
        let first = app.sel_approval.saturating_sub(shown - 1);
        let slots = Layout::vertical(vec![Constraint::Length(CARD_HEIGHT); shown]).split(cards);
        for (slot, (i, a)) in slots
            .iter()
            .zip(app.approvals.iter().enumerate().skip(first))
        {
            approval_card(f, *slot, a, app, t, i == app.sel_approval, now);
        }
    }

    let mut lines = vec![Line::from(s(" ANSWERED", t.bold(Tone::Accent)))];
    let width = answered.width as usize;
    for a in app
        .model
        .answers
        .iter()
        .rev()
        .take(answered.height.saturating_sub(1) as usize)
    {
        let (word, tone) = match a.verdict {
            Verdict::Approved => ("APPROVED", Tone::Ok),
            Verdict::Rejected => ("REJECTED", Tone::Bad),
            Verdict::Expired => ("EXPIRED", Tone::Bad),
        };
        let command = app.model.decision_of(&a.id).map_or("", |d| d.args.as_str());
        let how = if a.via.is_empty() {
            "expired before anyone answered".to_owned()
        } else {
            format!("via {}", a.via)
        };
        let tail = format!(
            "{how} · {} · session {}",
            a.rule,
            a.session.as_deref().unwrap_or("–")
        );
        let command_w = width.saturating_sub(1 + 10 + 10 + 14 + 2).clamp(10, 50) * 3 / 5;
        lines.push(Line::from(vec![
            s(
                format!(" {}  ", fit(&when(&a.ts, now), 8)),
                t.tone(Tone::Muted),
            ),
            s(fit(word, 10), t.bold(tone)),
            s(fit(&a.tool, 14), t.tone(Tone::Accent)),
            s(fit(command, command_w), t.tone(Tone::Ink)),
            s("  ", Style::new()),
            s(tail, t.tone(Tone::Muted)),
        ]));
    }
    if app.model.answers.is_empty() {
        lines.push(Line::from(s(
            " no request has been answered yet",
            t.tone(Tone::Dim),
        )));
    }
    f.render_widget(Paragraph::new(lines), answered);
}

fn approval_card(
    f: &mut Frame,
    area: Rect,
    a: &ApprovalInfo,
    app: &App,
    t: &Theme,
    selected: bool,
    now: DateTime<Local>,
) {
    // Die gewählte Karte trägt den Amber-Rand: auf sie wirken a und d.
    let edge = if selected { t.fg(t.warn) } else { t.fg(t.line) };
    let block = Block::new().borders(Borders::ALL).border_style(edge);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [head, input, rest] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .areas(inner);

    f.render_widget(
        Paragraph::new(Line::from(vec![
            s(" ", Style::new()),
            s(" WAITING ", t.chip(t.warn)),
            s("  ", Style::new()),
            s(a.tool.clone(), t.bold(Tone::Ink)),
            s(
                format!(
                    " · {} · {} · {}",
                    who(a.client.as_deref(), a.session.as_deref()),
                    a.model.as_deref().unwrap_or("–"),
                    when(&a.created, now)
                ),
                t.tone(Tone::Muted),
            ),
        ])),
        head,
    );
    let frame = Block::new()
        .borders(Borders::ALL)
        .border_style(t.fg(t.line));
    let box_inner = frame.inner(Rect {
        x: input.x + 1,
        width: input.width.saturating_sub(2),
        ..input
    });
    f.render_widget(
        frame,
        Rect {
            x: input.x + 1,
            width: input.width.saturating_sub(2),
            ..input
        },
    );
    f.render_widget(
        Paragraph::new(format!(
            " {}",
            truncate(&a.preview, box_inner.width.saturating_sub(2) as usize)
        ))
        .style(t.bold(Tone::Ink)),
        box_inner,
    );

    let left = app.expires_in(a);
    let until = (now + chrono::Duration::seconds(left as i64)).format("%H:%M:%S");
    let how = if a.kind == "chat" {
        "asked in the agent session"
    } else {
        "the agent is waiting"
    };
    let command = |verb: &str, key: &str, tone: Tone| {
        Line::from(vec![
            s(format!(" hedge {verb} {}", a.id), t.bold(Tone::Warn)),
            s("   or press ", t.tone(Tone::Dim)),
            s(key.to_owned(), t.bold(tone)),
        ])
    };
    let mut lines = vec![
        Line::from(vec![
            s(format!(" {} ", a.rule), t.bold(Tone::Ink)),
            s(a.reason.clone(), t.tone(Tone::Ink)),
        ]),
        Line::from(s(
            format!(
                " approval {} · expires {until} (in {}) · {how}",
                a.id,
                countdown(left)
            ),
            t.tone(Tone::Muted),
        )),
        command("approve", "a", Tone::Ok),
        command("deny", "d", Tone::Bad),
    ];
    if a.kind == "chat" {
        lines[1].push_span(s(
            format!(" · or reply `approve {}` there", a.id),
            t.tone(Tone::Muted),
        ));
    }
    f.render_widget(Paragraph::new(lines), rest);
}

// ---------- Permissions ----------

fn permissions_tab(f: &mut Frame, area: Rect, app: &App, t: &Theme, now: DateTime<Local>) {
    let all = app.decisions(Chip::All);
    let waiting = all
        .iter()
        .filter(|(_, fate)| *fate == Fate::Waiting)
        .count();
    let block = panel(
        "PERMISSIONS",
        format!("{} decisions · {waiting} waiting", all.len()),
        t,
    );
    let inner = block.inner(area);
    f.render_widget(block, area);
    let text = "Every decision that was not a plain allow, and what came of it. ← → narrows, enter opens the session.";
    let text = wrap(text, (inner.width as usize).saturating_sub(2), 2);
    let [chips, intro, head, body, detail] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(text.len() as u16 + 1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(5),
    ])
    .areas(inner);

    let mut row = vec![s(" ", Style::new())];
    for chip in Chip::ALL {
        let n = all.iter().filter(|(d, fate)| chip.wants(d, *fate)).count();
        // Schmal heißt die letzte Gruppe kurz „EXPIRED“.
        let title = match chip {
            Chip::Expired if inner.width < 112 => "EXPIRED",
            _ => chip.title(),
        };
        row.push(choice(format!("{title} {n}"), chip == app.chip, t));
    }
    f.render_widget(Paragraph::new(vec![Line::from(""), Line::from(row)]), chips);
    let mut lines = vec![Line::from("")];
    lines.extend(
        text.into_iter()
            .map(|x| Line::from(s(format!(" {x}"), t.tone(Tone::Muted)))),
    );
    f.render_widget(Paragraph::new(lines), intro);

    let rows = app.decisions(app.chip);
    let width = inner.width as usize;
    // Zeit, Session, Aufruf, Entscheidung, Ausgang stehen fest; Argumente
    // und Regel teilen sich den Rest, „wer · wann“ nur, wenn Platz ist.
    let who_w = if width >= 130 { 26 } else { 0 };
    let fixed = 1 + 12 + 10 + 12 + 9 + 16 + who_w;
    let rest = width.saturating_sub(fixed + 2);
    let (args_w, rule_w) = if width >= 104 {
        (rest * 2 / 5, rest * 3 / 5)
    } else {
        (rest, 0)
    };
    let col = |title: &str, w: usize| s(fit(title, w), t.tone(Tone::Muted));
    let mut titles = vec![
        s(" ", Style::new()),
        col("TIME", 12),
        col("SESSION", 10),
        col("CALL", 12),
        col("ARGUMENTS", args_w),
        s(" ", Style::new()),
        col("DECISION", 9),
    ];
    if rule_w > 0 {
        titles.push(col("RULE, IN WORDS", rule_w));
        titles.push(s(" ", Style::new()));
    }
    titles.push(col("OUTCOME", 16));
    if who_w > 0 {
        titles.push(col("WHO · WHEN", who_w));
    }
    f.render_widget(Paragraph::new(Line::from(titles)), head);

    let height = body.height as usize;
    let first = app.sel_decision.saturating_sub(height.saturating_sub(1));
    let lines: Vec<Line> = rows
        .iter()
        .enumerate()
        .skip(first)
        .take(height)
        .map(|(i, (d, fate))| {
            let on = i == app.sel_decision;
            let outcome = fate_span(*fate, t);
            let pad = 16usize.saturating_sub(outcome.width());
            let mut spans = vec![
                if on {
                    s("▌", t.bold(Tone::Accent))
                } else {
                    s(" ", Style::new())
                },
                s(fit(&when(&d.ts, now), 12), t.tone(Tone::Muted)),
                s(fit(&d.session, 10), t.tone(Tone::Ink)),
                s(fit(&d.call, 12), t.tone(Tone::Accent)),
                s(fit(&d.args, args_w), t.tone(Tone::Ink)),
                s(" ", Style::new()),
                s(fit(d.ruling.label(), 9), t.bold(ruling_tone(d.ruling))),
            ];
            if rule_w > 0 {
                spans.push(s(
                    fit(&rule_words(&d.rule, app), rule_w),
                    t.tone(Tone::Muted),
                ));
                spans.push(s(" ", Style::new()));
            }
            spans.push(outcome);
            spans.push(s(" ".repeat(pad), Style::new()));
            if who_w > 0 {
                spans.push(s(
                    fit(&answered_by(d, *fate, app, now), who_w),
                    t.tone(Tone::Muted),
                ));
            }
            let line = Line::from(spans);
            if on {
                select(line, inner.width, t)
            } else {
                line
            }
        })
        .collect();
    if lines.is_empty() {
        let text = if all.is_empty() {
            " hedge has not had to step in yet"
        } else {
            " nothing here – ← → picks another group, esc clears the search"
        };
        f.render_widget(Paragraph::new(text).style(t.tone(Tone::Dim)), body);
    } else {
        f.render_widget(Paragraph::new(lines), body);
    }

    // Die gewählte Zeile ausgeschrieben: was in der Tabelle abgeschnitten ist.
    let frame = Block::new()
        .borders(Borders::TOP)
        .border_style(t.fg(t.line));
    let room = frame.inner(detail);
    f.render_widget(frame, detail);
    let Some((d, fate)) = rows.get(app.sel_decision) else {
        return;
    };
    let text_w = (room.width as usize).saturating_sub(13);
    let mut lines: Vec<Line> = Vec::new();
    let mut put = |key: &str, value: &str, tone: Tone, max: usize| {
        for (i, part) in wrap(value, text_w, max).into_iter().enumerate() {
            lines.push(Line::from(vec![
                s(
                    format!(" {}", fit(if i == 0 { key } else { "" }, 11)),
                    t.tone(Tone::Muted),
                ),
                s(part, t.tone(tone)),
            ]));
        }
    };
    put(
        "ARGUMENTS",
        if d.args.is_empty() { "–" } else { &d.args },
        Tone::Ink,
        2,
    );
    put("RULE", &rule_words(&d.rule, app), Tone::Ink, 1);
    let next = match fate {
        Fate::Waiting => "waiting for you – a approve · d deny".to_owned(),
        Fate::Blocked if d.ruling == Ruling::Block => {
            "the request never reached the model".to_owned()
        }
        Fate::Blocked => "the call never reached the agent; the model was told why".to_owned(),
        Fate::Flagged => "ran – tools.enforce is off, hedge only marks".to_owned(),
        Fate::Masked => "sent with the findings masked".to_owned(),
        Fate::Approved { ran: true } => format!(
            "approved {} – the call ran once",
            answered_by(d, *fate, app, now)
        ),
        Fate::Approved { ran: false } => format!(
            "approved {} – the agent has not repeated the call",
            answered_by(d, *fate, app, now)
        ),
        Fate::Rejected => format!(
            "rejected {} – the call did not run",
            answered_by(d, *fate, app, now)
        ),
        Fate::Expired => "nobody answered in time – the call did not run".to_owned(),
        Fate::Unanswered => "no answer on record – the call did not run".to_owned(),
    };
    put("OUTCOME", &next, Tone::Ink, 1);
    f.render_widget(Paragraph::new(lines), room);
}

/// Wer entschieden hat und wann – bei Regeln, die allein entscheiden, die Regel.
fn answered_by(d: &Decision, fate: Fate, app: &App, now: DateTime<Local>) -> String {
    let answer = d.approval.as_deref().and_then(|id| app.model.answer(id));
    match (fate, answer) {
        (Fate::Waiting, _) => "–".to_owned(),
        (_, Some(a)) if a.via.is_empty() => format!("nobody · {}", when(&a.ts, now)),
        (_, Some(a)) => format!("via {} · {}", a.via, when(&a.ts, now)),
        (Fate::Blocked, _) => "the rule decides alone".to_owned(),
        _ => "–".to_owned(),
    }
}

// ---------- Fußzeile und Hilfe ----------

fn footer(f: &mut Frame, area: Rect, app: &App, t: &Theme) {
    if app.mode == Mode::Filter {
        let line = Line::from(vec![
            s(" / ", t.bold(Tone::Accent)),
            s(app.query.clone(), t.bold(Tone::Ink)),
            s("▏", t.tone(Tone::Accent)),
            s("   enter keep · esc clear", t.tone(Tone::Muted)),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }
    if let Some(toast) = app
        .toast
        .as_ref()
        .filter(|x| x.at.elapsed().as_secs() < TOAST_SECS)
    {
        f.render_widget(
            Paragraph::new(format!(" {}", toast.text)).style(t.bold(toast.tone)),
            area,
        );
        return;
    }
    let keys: &[(&str, &str)] = match app.tab {
        Tab::Overview => &[
            ("↑↓", "select"),
            ("↵", "open session"),
            ("a/d", "approve/deny"),
            ("f", "alerts only"),
            ("/", "filter"),
            ("1-4", "tabs"),
            ("?", "help"),
            ("q", "quit"),
        ],
        Tab::Live => &[
            ("↑↓", "row"),
            ("←→", "session"),
            ("n/N", "next/prev decision"),
            ("f", "tape filter"),
            ("a/d", "approve/deny"),
            ("/", "filter"),
            ("esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        Tab::Approvals => &[
            ("↑↓", "select"),
            ("a", "approve"),
            ("d", "deny"),
            ("1-4", "tabs"),
            ("?", "help"),
            ("q", "quit"),
        ],
        Tab::Permissions => &[
            ("↑↓", "select"),
            ("←→", "group"),
            ("↵", "open session"),
            ("a/d", "approve/deny"),
            ("/", "filter"),
            ("1-4", "tabs"),
            ("?", "help"),
            ("q", "quit"),
        ],
    };
    let mut left = vec![s(" ", Style::new())];
    for (k, what) in keys {
        left.push(s(*k, t.bold(Tone::Ink)));
        left.push(s(format!(" {what}   "), t.tone(Tone::Muted)));
    }
    let mut right = Vec::new();
    if !app.query.is_empty() && app.tab != Tab::Live {
        right.push(s(format!("filter: {} ", app.query), t.tone(Tone::Accent)));
    }
    let [l, r] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(width_of(&right))]).areas(area);
    f.render_widget(Paragraph::new(Line::from(left)), l);
    f.render_widget(Paragraph::new(Line::from(right)), r);
}

fn help(f: &mut Frame, screen: Rect, t: &Theme) {
    let rows: [(&str, &str); 16] = [
        ("1 2 3 4 · tab", "overview · live · approvals · permissions"),
        ("↑ ↓ · j k", "move the selection"),
        ("pgup pgdn · g G", "jump"),
        ("enter", "open the selected session in live"),
        (
            "← → · h l",
            "live: switch session · permissions: switch group",
        ),
        ("n · N", "live: next / previous decision on the tape"),
        ("f", "live: all · alerts · decisions · approvals"),
        ("esc", "back · clear the filter"),
        ("a", "approve the request shown in the bar (asks y)"),
        ("d", "deny the request shown in the bar"),
        ("/", "filter by session, client, model, tool, rule"),
        ("?", "this help"),
        ("q · ctrl-c", "quit (hedge keeps running)"),
        ("", ""),
        ("", "WAITING waits for you · DENIED and BLOCKED did not run"),
        ("", "MASKED was sent without the secret · FLAGGED ran"),
    ];
    let (w, h) = (76.min(screen.width), rows.len() as u16 + 2);
    let area = Rect {
        x: screen.x + (screen.width - w) / 2,
        y: screen.y + screen.height.saturating_sub(h) / 2,
        width: w,
        height: h.min(screen.height),
    };
    let lines: Vec<Line> = rows
        .iter()
        .map(|(k, what)| {
            Line::from(vec![
                s(format!(" {}", fit(k, 18)), t.bold(Tone::Ink)),
                s(*what, t.tone(Tone::Muted)),
            ])
        })
        .collect();
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Left)
            .block(panel("KEYS", "any key closes".to_owned(), t).style(Style::new().bg(t.raised))),
        area,
    );
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::*;
    use crate::tui::model::Model;
    use crate::tui::model::tests::{chain, finding, request, tool};
    use crate::tui::theme::Depth;
    use crate::witness::Record;

    fn approval(id: &str, session: &str) -> ApprovalInfo {
        ApprovalInfo {
            id: id.into(),
            created: "2026-11-10T12:00:00.000Z".into(),
            expires_in_secs: 252,
            upstream: "anthropic".into(),
            client: None,
            session: Some(session.into()),
            model: Some("claude-sonnet-4-5".into()),
            tool: "Bash".into(),
            preview: "git push --force origin main".into(),
            rule: "HEDGE-SHELL-003".into(),
            reason: "force push rewrites remote history".into(),
            kind: "chat".into(),
        }
    }

    fn answer(detail: &str) -> Record {
        let mut r = request("bbbb2222");
        r.event = Some("approval".into());
        r.detail = Some(detail.into());
        r
    }

    /// Zwei Sessions: eine ruhige, eine mit Fund, gestopptem und
    /// angehaltenem Tool-Aufruf.
    fn app_of(extra: Vec<Record>) -> App {
        let mut redact = request("bbbb2222");
        redact.action = "redact".into();
        redact.findings = vec![finding("email", "p…@x.example", false)];
        let mut stop = request("bbbb2222");
        stop.tools = vec![tool("Read", "deny", Some("HEDGE-CRED-001"))];
        let mut hold = request("bbbb2222");
        hold.tools = vec![tool("Bash", "held", Some("HEDGE-SHELL-003"))];
        let mut records = vec![request("aaaa1111"), redact, stop, hold];
        records.extend(extra);
        let (_dir, entries, key) = chain(records);
        let mut app = App::new(
            Model::new(Some(key)),
            "http://127.0.0.1:18765".into(),
            false,
        );
        app.rules.insert(
            "HEDGE-SHELL-003".into(),
            "force push rewrites remote history".into(),
        );
        app.ingest(entries);
        app
    }

    fn app() -> App {
        app_of(Vec::new())
    }

    fn render(app: &App, depth: Depth, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        let theme = Theme::new(depth);
        // Weit in der Zukunft: Jede Session ist „idle“, Zeiten zeigen das Datum.
        let now = Local.with_ymd_and_hms(2030, 1, 1, 12, 0, 0).unwrap();
        terminal.draw(|f| draw(f, app, &theme, now)).expect("draw");
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn has(screen: &str, words: &[&str]) {
        for word in words {
            assert!(screen.contains(word), "missing {word:?}\n{screen}");
        }
    }

    #[test]
    fn overview_shows_sessions_counters_and_the_live_stream() {
        let app = app();
        let screen = render(&app, Depth::True, 140, 32);

        has(
            &screen,
            &[
                "H E D G E",
                "OVERVIEW   LIVE   APPROVALS   PERMISSIONS",
                "CHAIN ✓ 4 records",
                "2 sessions · 0 active",
                "BLOCKED",
                "HELD",
                "FINDINGS",
                "WITNESS",
                "✓ chain",
                "○ idle",
                "STOP",
                "REDACT",
                "HEDGE-CRED-001 · denied",
                "masked",
            ],
        );
        // Zuletzt aktive Session zuerst.
        assert!(screen.find("bbbb2222").expect("row") < screen.find("aaaa1111").expect("row"));
        // Ohne Central-Mode gibt es keine Client-Spalte.
        assert!(!screen.contains("CLIENT"));
        // Nichts wartet mehr: keine Leiste, und der alte Aufruf war nur „held“.
        assert!(!screen.contains("WAITING FOR YOU"));
        assert!(!screen.contains(" HOLD "));
        assert!(screen.contains("held  "));
    }

    #[test]
    fn a_waiting_request_is_impossible_to_miss() {
        let mut app = app();
        app.on_control(Ok(vec![approval("apr-1", "bbbb2222")]), None);
        let screen = render(&app, Depth::True, 140, 32);

        has(
            &screen,
            &[
                "WAITING FOR YOU 1",
                "● LIVE",
                "git push --force origin main",
                "expires in 4:1",
                "a approve",
                "d deny",
            ],
        );
        // Die Fläche HOLD steht in der Leiste, an der Session und am Eintrag.
        assert_eq!(screen.matches(" HOLD ").count(), 3, "{screen}");
        assert!(!screen.contains("held  "));

        press(&mut app, KeyCode::Char('a'));
        let screen = render(&app, Depth::True, 140, 32);
        has(&screen, &["APPROVE?", "y yes, run it once"]);
    }

    #[test]
    fn on_a_narrow_terminal_the_command_survives_and_the_reason_gives_way() {
        let mut app = app();
        app.on_control(Ok(vec![approval("apr-1", "bbbb2222")]), None);
        let screen = render(&app, Depth::True, 80, 24);

        has(
            &screen,
            &[
                "git push --force origin main",
                "a approve",
                "SESSION ",
                "BLOCKED",
                "FINDINGS",
                "WITNESS",
                "TOKENS TODAY",
                // Kopfzeile: Reiter bleiben ganz, rechts entfällt, was nicht passt.
                "OVERVIEW   LIVE   APPROVALS 1   PERMISSIONS",
                "● LIVE",
            ],
        );
        assert!(!screen.contains("rewrites remote history"));
        // Schmale Terminals lassen Start und Modell weg, nie die Zahlen.
        assert!(!screen.contains("STARTED"));
        assert!(!screen.contains("MODEL"));
    }

    #[test]
    fn columns_give_way_in_a_fixed_order() {
        let titles = |w: u16, clients: bool| -> Vec<&str> {
            columns_for(w, clients)
                .into_iter()
                .map(|i| COLUMNS[i].title)
                .collect()
        };
        assert_eq!(titles(200, true).len(), 13);
        assert!(!titles(200, false).contains(&"CLIENT"));
        let narrow = titles(78, true);
        for gone in ["MODEL", "CLIENT", "STARTED", "TOKENS"] {
            assert!(!narrow.contains(&gone), "{narrow:?}");
        }
        for kept in [
            "SESSION", "REQS", "BLOCKED", "HELD", "FLAGGED", "FINDINGS", "WITNESS",
        ] {
            assert!(titles(70, true).contains(&kept));
        }
    }

    #[test]
    fn live_shows_sessions_the_tape_and_the_selected_record() {
        let mut app = app();
        press(&mut app, KeyCode::Char('2'));
        let screen = render(&app, Depth::True, 200, 40);

        has(
            &screen,
            &[
                // links
                "SESSIONS",
                "▌all sessions  2",
                "3 requests · 2 calls",
                "1 blocked 1 held 1 found",
                "nothing stopped",
                "TOOL MIX",
                // Band
                "TAPE  All  Alerts  Decisions  Approvals",
                "EVT    TOOL      TARGET / TEXT",
                "MODEL",
                "HOLD   Bash      git push --force origin main · HEDGE-SHELL-003",
                "UNANSWERED",
                "DENY   Read      git push --force origin main · HEDGE-CRED-001",
                "DENIED",
                "FIND             e-mail address p…@x.example · messages[3].content",
                "MASKED",
                // rechts: der neueste Eintrag ist ausgewählt
                "DETAIL",
                "record #4",
                "MODEL      claude-sonnet-4-5",
                "PROMPT     forwarded unchanged",
                "TOKENS     1.0k in · 200 out · 0 cached",
                "SIGNED BY",
                "POLICY",
                "all sessions",
                "DENIED     1",
                "HELD       1",
                "MASKED     1",
            ],
        );

        // Auf dem angehaltenen Aufruf: was, welche Regel, was kam heraus.
        press(&mut app, KeyCode::Char('n'));
        let screen = render(&app, Depth::True, 200, 40);
        has(
            &screen,
            &[
                "CALL       Bash",
                "INPUT      git push --force origin main",
                "RULE       HEDGE-SHELL-003 force push",
                "OUTCOME    UNANSWERED",
                "APPROVAL   apr-1",
            ],
        );

        // Schmal bleibt das Band; Liste und Detail weichen.
        let narrow = render(&app, Depth::True, 90, 30);
        has(&narrow, &["TAPE", "HOLD   Bash"]);
        assert!(!narrow.contains("TOOL MIX"));
        assert!(!narrow.contains("DETAIL"));
    }

    #[test]
    fn an_opened_session_shows_its_facts_proof_and_only_its_tape() {
        let mut app = app();
        press(&mut app, KeyCode::Enter);
        let screen = render(&app, Depth::True, 170, 40);

        has(
            &screen,
            &[
                "← esc  bbbb2222",
                "✓ VERIFIED · 3 requests · 2 tool calls · 1 blocked · 1 held",
                "EXPORT hedge export --session bbbb2222 -o run.json",
                "VERIFY hedge verify --bundle run.json",
                "this session",
                "▌bbbb2222",
            ],
        );
        // Das Band zeigt nur diese Session und braucht die Spalte nicht mehr.
        assert!(!screen.contains("SESSION   EVT"), "{screen}");
        assert_eq!(app.rows().count(), 6);
    }

    #[test]
    fn a_broken_chain_is_loud() {
        let (_dir, mut entries, key) = chain(vec![request("aaaa1111"), request("aaaa1111")]);
        entries[1].tokens_out = Some(1);
        let mut app = App::new(Model::new(Some(key)), "http://x".into(), false);
        app.ingest(entries);
        let screen = render(&app, Depth::True, 140, 32);
        has(&screen, &["CHAIN ✗", "problems", "✗ broken"]);

        press(&mut app, KeyCode::Enter);
        let screen = render(&app, Depth::True, 170, 32);
        has(&screen, &["✗ CHAIN BROKEN"]);
    }

    #[test]
    fn approvals_show_the_call_the_rule_and_how_to_answer() {
        let mut app = app_of(vec![
            answer("apr-9 approved via chat · Bash · HEDGE-SHELL-003"),
            answer("apr-8 rejected via control api · Edit · no-billing"),
            answer("apr-7 timed out after 5m · Bash · HEDGE-SHELL-004"),
        ]);
        press(&mut app, KeyCode::Char('3'));
        app.on_control(Ok(vec![approval("apr-1", "bbbb2222")]), None);
        let screen = render(&app, Depth::True, 150, 40);

        has(
            &screen,
            &[
                "APPROVALS",
                "1 waiting · 3 answered",
                "An answer binds to the exact call",
                " WAITING   Bash · bbbb2222 · claude-sonnet-4-5",
                "│ git push --force origin main",
                "HEDGE-SHELL-003 force push rewrites remote history",
                "approval apr-1 · expires 12:04:1",
                "asked in the agent session · or reply `approve apr-1` there",
                "hedge approve apr-1   or press a",
                "hedge deny apr-1   or press d",
                "ANSWERED",
                "EXPIRED   Bash",
                "expired before anyone answered · HEDGE-SHELL-004",
                "REJECTED  Edit",
                "via control api · no-billing",
                "APPROVED  Bash",
                "via chat · HEDGE-SHELL-003 · session bbbb2222",
            ],
        );
        // Neueste Antwort zuerst.
        assert!(screen.find("EXPIRED   Bash").unwrap() < screen.find("APPROVED  Bash").unwrap());

        app.on_control(
            Err("cannot reach hedge at http://127.0.0.1:18765".into()),
            None,
        );
        let screen = render(&app, Depth::True, 150, 40);
        has(
            &screen,
            &[
                "○ PROXY OFFLINE",
                "cannot reach hedge at http://127.0.0.1:18765",
                "0 waiting · 3 answered",
            ],
        );
    }

    #[test]
    fn permissions_show_every_decision_and_what_came_of_it() {
        let mut app = app_of(vec![answer(
            "apr-1 rejected via control api · Bash · HEDGE-SHELL-003",
        )]);
        press(&mut app, KeyCode::Char('4'));
        let screen = render(&app, Depth::True, 170, 36);

        has(
            &screen,
            &[
                "PERMISSIONS",
                "3 decisions · 0 waiting",
                " ALL 3  WAITING 0  BLOCKED 1  HELD 1  FLAGGED 0  MASKED 1  APPROVED 0  REJECTED 1 ",
                "EXPIRED OR UNANSWERED 0",
                "Every decision that was not a plain allow",
                "TIME        SESSION   CALL        ARGUMENTS",
                "DECISION",
                "RULE, IN WORDS",
                "OUTCOME",
                "WHO · WHEN",
                "HOLD",
                "HEDGE-SHELL-003 force push rewrites remote history",
                "REJECTED",
                "via control api ·",
                "DENY",
                "BLOCKED",
                "the rule decides alone",
                "REDACT",
                "MASKED · SENT",
                // unten: die gewählte (neueste) Zeile ausgeschrieben
                "ARGUMENTS  git push --force origin main",
                "OUTCOME    rejected via control api",
                "the call did not run",
            ],
        );

        // Wartet die Anfrage noch, steht sie als Fläche da und a/d wirken auf sie.
        let mut app = app_of(Vec::new());
        press(&mut app, KeyCode::Char('4'));
        app.on_control(Ok(vec![approval("apr-1", "bbbb2222")]), None);
        let screen = render(&app, Depth::True, 170, 36);
        has(
            &screen,
            &[
                "WAITING 1",
                " WAITING ",
                "waiting for you – a approve · d deny",
            ],
        );
        assert_eq!(app.current_approval().map(|a| a.id.as_str()), Some("apr-1"));

        // → REJECTED-Gruppe ist hier leer und sagt das auch.
        for _ in 0..7 {
            press(&mut app, KeyCode::Right);
        }
        assert_eq!(app.chip, Chip::Rejected);
        let screen = render(&app, Depth::True, 170, 36);
        has(&screen, &["nothing here – ← → picks another group"]);
    }

    #[test]
    fn empty_states_tell_what_to_do() {
        let mut app = App::new(Model::new(None), "http://127.0.0.1:18765".into(), false);
        let screen = render(&app, Depth::True, 140, 32);
        has(
            &screen,
            &[
                "start `hedge run` and point your agent at http://127.0.0.1:18765",
                "CHAIN ? no public key",
            ],
        );
        press(&mut app, KeyCode::Char('2'));
        has(
            &render(&app, Depth::True, 140, 32),
            &["waiting for the first request"],
        );
        press(&mut app, KeyCode::Char('3'));
        has(
            &render(&app, Depth::True, 140, 32),
            &["no request has been answered yet"],
        );
        press(&mut app, KeyCode::Char('4'));
        has(
            &render(&app, Depth::True, 140, 32),
            &["hedge has not had to step in yet"],
        );

        let tiny = render(&app, Depth::True, 60, 10);
        assert!(tiny.contains("needs at least 72×14"));
    }

    #[test]
    fn wrap_breaks_at_spaces_cuts_long_words_and_marks_what_is_left_out() {
        assert_eq!(wrap("one two three", 9, 5), vec!["one two", "three"]);
        assert_eq!(wrap("abcdefghijkl", 8, 5), vec!["abcdefgh", "ijkl"]);
        assert_eq!(wrap("", 10, 5), Vec::<String>::new());
        let cut = wrap("aaaa bbbb cccc dddd eeee", 9, 2);
        assert_eq!(cut.len(), 2);
        assert!(cut[1].ends_with('…'), "{cut:?}");
    }

    #[test]
    fn every_view_renders_at_every_depth_and_size() {
        let mut app = app_of(vec![answer(
            "apr-9 approved via chat · Bash · HEDGE-SHELL-003",
        )]);
        app.on_control(
            Ok(vec![
                approval("apr-1", "bbbb2222"),
                approval("apr-2", "aaaa1111"),
            ]),
            None,
        );
        let keys = [
            KeyCode::Char('?'),
            KeyCode::Esc,
            KeyCode::Enter,
            KeyCode::Down,
            KeyCode::Char('n'),
            KeyCode::Right,
            KeyCode::Esc,
            KeyCode::Char('2'),
            KeyCode::Char('f'),
            KeyCode::Char('f'),
            KeyCode::End,
            KeyCode::Char('/'),
            KeyCode::Char('x'),
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Char('3'),
            KeyCode::Down,
            KeyCode::Char('a'),
            KeyCode::Esc,
            KeyCode::Char('4'),
            KeyCode::Right,
            KeyCode::Left,
            KeyCode::End,
        ];
        for key in keys {
            press(&mut app, key);
            for depth in [Depth::True, Depth::Ansi256, Depth::Ansi16, Depth::Mono] {
                for (w, h) in [(72, 14), (80, 24), (100, 30), (124, 40), (250, 70), (10, 3)] {
                    let screen = render(&app, depth, w, h);
                    assert_eq!(screen.lines().count(), h as usize);
                }
            }
        }
    }
}
