//! Telemetrie: Traces und Metriken per OpenTelemetry (OTLP/HTTP).
//!
//! Jede Anfrage wird ein Span, alle Anfragen einer Agent-Session landen im
//! selben Trace. Der Span trägt Sequenznummer und Hash des Witness-Eintrags:
//! Das Telemetrie-Backend ist damit ein externer Anker der Kette – wer das
//! Witness-Ende abschneidet oder neu schreibt, widerspricht den Traces.
//!
//! Wie überall gilt: kein Prompt-Text, keine Credentials. Nur Metadaten.

use std::time::{Duration, SystemTime};

use opentelemetry::metrics::{Counter, Gauge, Histogram, MeterProvider as _, ObservableGauge};
use opentelemetry::trace::{
    Span as _, SpanContext, SpanId, SpanKind, Status, TraceContextExt, TraceFlags, TraceId,
    TraceState, Tracer as _, TracerProvider as _,
};
use opentelemetry::{Context, KeyValue};
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};
use sha2::{Digest, Sha256};

use crate::config::Telemetry as TelemetryCfg;
use crate::witness::{Anchor, Record};

pub struct Telemetry {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
    tracer: SdkTracer,
    requests: Counter<u64>,
    findings: Counter<u64>,
    tool_calls: Counter<u64>,
    tokens: Counter<u64>,
    witness_errors: Counter<u64>,
    duration: Histogram<f64>,
    presidio_texts: Counter<u64>,
    presidio_unscanned: Counter<u64>,
    presidio_duration: Histogram<f64>,
    presidio_up: Gauge<u64>,
    /// Herzschlag: Bleibt er aus, steht Hedge. Ohne ihn sähe ein Ausfall
    /// in den Metriken aus wie ein ruhiger Nachmittag.
    _up: ObservableGauge<u64>,
}

/// Führt `f` auf einem eigenen Thread aus. Der OTLP-Exporter benutzt einen
/// blockierenden HTTP-Client, der nicht innerhalb der tokio-Runtime gebaut
/// oder abgebaut werden darf.
fn off_runtime<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::spawn(f)
        .join()
        .expect("telemetry thread panicked")
}

impl Telemetry {
    /// Baut Exporter und Instrumente. `Ok(None)`, wenn Telemetrie aus ist.
    pub fn init(cfg: &TelemetryCfg) -> Result<Option<Self>, String> {
        if !cfg.enabled {
            return Ok(None);
        }
        let cfg = cfg.clone();
        off_runtime(move || Self::build(&cfg)).map(Some)
    }

    fn build(cfg: &TelemetryCfg) -> Result<Self, String> {
        let base = cfg.endpoint.trim_end_matches('/');
        let resource = Resource::builder()
            .with_service_name(cfg.service_name.clone())
            .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
            .build();

        let span_exporter = SpanExporter::builder()
            .with_http()
            .with_endpoint(format!("{base}/v1/traces"))
            .with_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| format!("telemetry: cannot build trace exporter: {e}"))?;
        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(span_exporter)
            .with_resource(resource.clone())
            .build();

        let metric_exporter = MetricExporter::builder()
            .with_http()
            .with_endpoint(format!("{base}/v1/metrics"))
            .with_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| format!("telemetry: cannot build metric exporter: {e}"))?;
        let reader = PeriodicReader::builder(metric_exporter)
            .with_interval(Duration::from_secs(cfg.interval_secs.max(1)))
            .build();
        let meter_provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource)
            .build();

        let tracer = tracer_provider.tracer("hedge");
        let meter = meter_provider.meter("hedge");
        Ok(Self {
            requests: meter
                .u64_counter("hedge_requests")
                .with_description("Requests seen by hedge, by outcome")
                .build(),
            findings: meter
                .u64_counter("hedge_findings")
                .with_description("Secrets and PII found, by kind, severity and direction")
                .build(),
            tool_calls: meter
                .u64_counter("hedge_tool_calls")
                .with_description("Tool calls requested by the model, by tool and decision")
                .build(),
            tokens: meter
                .u64_counter("hedge_tokens")
                .with_description("Tokens by type (input, output, cached)")
                .build(),
            witness_errors: meter
                .u64_counter("hedge_witness_errors")
                .with_description("Failed writes to the witness chain")
                .build(),
            duration: meter
                .f64_histogram("hedge_request_duration_ms")
                .with_description("Time from request to end of response")
                .with_boundaries(vec![
                    5.0, 25.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0, 30000.0,
                    60000.0, 120000.0,
                ])
                .build(),
            presidio_texts: meter
                .u64_counter("hedge_presidio_texts")
                .with_description("Texts handed to Presidio, by result (analyzed, cached, failed)")
                .build(),
            presidio_unscanned: meter
                .u64_counter("hedge_presidio_unscanned")
                .with_description(
                    "Requests Presidio could not check, by outcome (forwarded, blocked) and reason",
                )
                .build(),
            presidio_duration: meter
                .f64_histogram("hedge_presidio_duration_ms")
                .with_description("Duration of a single Presidio analysis call")
                .with_boundaries(vec![
                    5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
                ])
                .build(),
            presidio_up: meter
                .u64_gauge("hedge_presidio_up")
                .with_description(
                    "1 while Presidio is ready, 0 while it is starting or unavailable",
                )
                .build(),
            _up: meter
                .u64_observable_gauge("hedge_up")
                .with_description("1 while hedge is running (heartbeat)")
                .with_callback(|observer| observer.observe(1, &[]))
                .build(),
            tracer,
            tracer_provider,
            meter_provider,
        })
    }

    /// Meldet, was Presidio für eine Anfrage getan hat.
    pub fn presidio_scan(&self, scan: &crate::presidio::Scan, blocked: bool) {
        for (result, n) in [
            ("analyzed", scan.analyzed),
            ("cached", scan.cached),
            ("failed", scan.failed),
        ] {
            if n > 0 {
                self.presidio_texts
                    .add(n, &[KeyValue::new("result", result)]);
            }
        }
        for ms in &scan.durations_ms {
            self.presidio_duration.record(*ms as f64, &[]);
        }
        if let Some(gap) = &scan.gap {
            self.presidio_unscanned.add(
                1,
                &[
                    KeyValue::new("outcome", if blocked { "blocked" } else { "forwarded" }),
                    KeyValue::new("reason", gap.flag()),
                ],
            );
        }
    }

    /// Hält fest, ob Presidio gerade bereit ist.
    pub fn presidio_up(&self, up: bool) {
        self.presidio_up.record(u64::from(up), &[]);
    }

    /// Meldet eine abgeschlossene Anfrage.
    pub fn record(&self, r: &Record, anchor: Option<&Anchor>) {
        let client = r.client.clone().unwrap_or_else(|| "local".into());
        let model = r.model.clone().unwrap_or_else(|| "-".into());

        self.requests.add(
            1,
            &[
                KeyValue::new("upstream", r.upstream.clone()),
                KeyValue::new("action", r.action.clone()),
                KeyValue::new("mode", r.mode.clone()),
                KeyValue::new("client", client.clone()),
            ],
        );
        self.duration.record(
            r.duration_ms as f64,
            &[
                KeyValue::new("upstream", r.upstream.clone()),
                KeyValue::new("action", r.action.clone()),
            ],
        );
        for (direction, list) in [("request", &r.findings), ("response", &r.response_findings)] {
            // Wiederholungen aus der mitgeschickten Historie zählen nicht:
            // Ein einmal getippter Key soll einen Alert auslösen, nicht zehn.
            for f in list.iter().filter(|f| !f.repeat) {
                self.findings.add(
                    1,
                    &[
                        KeyValue::new("kind", f.kind.clone()),
                        KeyValue::new("severity", f.severity.clone()),
                        KeyValue::new("direction", direction),
                        KeyValue::new("client", client.clone()),
                    ],
                );
            }
        }
        for t in &r.tools {
            self.tool_calls.add(
                1,
                &[
                    KeyValue::new("tool", t.name.clone()),
                    KeyValue::new("decision", t.decision.clone()),
                    KeyValue::new("rule", t.rule.clone().unwrap_or_else(|| "-".into())),
                ],
            );
        }
        for (kind, n) in [
            ("input", r.tokens_in),
            ("output", r.tokens_out),
            ("cached", r.tokens_cached),
        ] {
            if let Some(n) = n.filter(|n| *n > 0) {
                self.tokens.add(
                    n,
                    &[
                        KeyValue::new("type", kind),
                        KeyValue::new("upstream", r.upstream.clone()),
                        KeyValue::new("model", model.clone()),
                        KeyValue::new("client", client.clone()),
                    ],
                );
            }
        }

        // Span: rückwirkend mit echter Start- und Endzeit.
        let end = SystemTime::now();
        let start = end - Duration::from_millis(r.duration_ms);
        let mut attrs = vec![
            KeyValue::new("hedge.upstream", r.upstream.clone()),
            KeyValue::new("hedge.action", r.action.clone()),
            KeyValue::new("hedge.mode", r.mode.clone()),
            KeyValue::new("hedge.client", client),
            KeyValue::new("gen_ai.request.model", model),
            KeyValue::new(
                "hedge.findings",
                r.findings.iter().filter(|f| !f.repeat).count() as i64,
            ),
            KeyValue::new(
                "hedge.findings.repeated",
                r.findings.iter().filter(|f| f.repeat).count() as i64,
            ),
            KeyValue::new("hedge.response_findings", r.response_findings.len() as i64),
            KeyValue::new("hedge.tools", r.tools.len() as i64),
            KeyValue::new("hedge.stream", r.stream),
            KeyValue::new("hedge.aborted", r.aborted),
        ];
        let mut push = |k: &'static str, v: Option<String>| {
            if let Some(v) = v {
                attrs.push(KeyValue::new(k, v));
            }
        };
        push("session.id", r.session.clone());
        push("hedge.event", r.event.clone());
        push("hedge.detail", r.detail.clone());
        push("gen_ai.response.finish_reason", r.stop_reason.clone());
        push(
            "hedge.finding.kinds",
            joined(r.findings.iter().map(|f| f.kind.as_str())),
        );
        push("hedge.flags", joined(r.flags.iter().map(String::as_str)));
        push(
            "hedge.tools.flagged",
            joined(
                r.tools
                    .iter()
                    .filter(|t| t.rule.is_some())
                    .map(|t| t.name.as_str()),
            ),
        );
        push("hedge.witness.hash", anchor.map(|a| a.hash.clone()));
        if let Some(a) = anchor {
            attrs.push(KeyValue::new("hedge.witness.seq", a.seq as i64));
        }
        if let Some(s) = r.status {
            attrs.push(KeyValue::new("http.response.status_code", s as i64));
        }
        for (k, n) in [
            ("gen_ai.usage.input_tokens", r.tokens_in),
            ("gen_ai.usage.output_tokens", r.tokens_out),
            ("hedge.tokens.cached", r.tokens_cached),
        ] {
            if let Some(n) = n {
                attrs.push(KeyValue::new(k, n as i64));
            }
        }

        let name = match &r.event {
            Some(event) => format!("hedge {event}"),
            None => format!("{} {}", r.method, r.path),
        };
        let builder = self
            .tracer
            .span_builder(name)
            .with_kind(SpanKind::Server)
            .with_start_time(start)
            .with_attributes(attrs);
        let parent = match &r.session {
            Some(session) => Context::new().with_remote_span_context(session_context(session)),
            None => Context::new(),
        };
        let mut span = self.tracer.build_with_context(builder, &parent);
        if r.action == "block" {
            span.set_status(Status::error(
                r.detail
                    .clone()
                    .unwrap_or_else(|| "blocked by hedge".into()),
            ));
        } else if r.status.is_some_and(|s| s >= 500) || r.aborted {
            span.set_status(Status::error("upstream error or aborted stream"));
        }
        span.end_with_timestamp(end);
    }

    pub fn witness_error(&self) {
        self.witness_errors.add(1, &[]);
    }

    /// Schreibt alles Ausstehende hinaus und beendet die Exporter.
    pub fn shutdown(self) {
        off_runtime(move || {
            let _ = self.tracer_provider.shutdown();
            let _ = self.meter_provider.shutdown();
        });
    }

    /// Erzwingt den Export (für Tests und vor dem Beenden).
    pub fn flush(&self) {
        // Scoped Thread: außerhalb der Runtime, ohne die Provider zu klonen
        // (ein Klon, der fällt, würde als "letzte Referenz" missverstanden).
        std::thread::scope(|s| {
            let _ = s
                .spawn(|| {
                    let _ = self.tracer_provider.force_flush();
                    let _ = self.meter_provider.force_flush();
                })
                .join();
        });
    }
}

fn joined<'a>(items: impl Iterator<Item = &'a str>) -> Option<String> {
    let mut v: Vec<&str> = items.collect();
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    v.dedup();
    Some(v.join(","))
}

/// Alle Anfragen einer Session teilen sich Trace-ID und (gedachten)
/// Wurzel-Span, beide aus der Session-ID abgeleitet.
fn session_context(session: &str) -> SpanContext {
    let digest = Sha256::digest(format!("hedge-session:{session}").as_bytes());
    let mut trace = [0u8; 16];
    let mut span = [0u8; 8];
    trace.copy_from_slice(&digest[..16]);
    span.copy_from_slice(&digest[16..24]);
    SpanContext::new(
        TraceId::from_bytes(trace),
        SpanId::from_bytes(span),
        TraceFlags::SAMPLED,
        true,
        TraceState::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_context_is_stable_and_valid() {
        let a = session_context("abcd1234");
        let b = session_context("abcd1234");
        let c = session_context("other");
        assert!(a.is_valid());
        assert_eq!(a.trace_id(), b.trace_id());
        assert_eq!(a.span_id(), b.span_id());
        assert_ne!(a.trace_id(), c.trace_id());
    }

    #[test]
    fn disabled_telemetry_builds_nothing() {
        assert!(Telemetry::init(&TelemetryCfg::default()).unwrap().is_none());
    }

    #[test]
    fn joined_dedups_and_sorts() {
        assert_eq!(joined(["b", "a", "b"].into_iter()).as_deref(), Some("a,b"));
        assert_eq!(joined(std::iter::empty()), None);
    }
}
