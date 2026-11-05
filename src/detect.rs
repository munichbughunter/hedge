use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub detector: &'static str,
    pub kind: &'static str,
    pub severity: Severity,
    pub start: usize,
    pub end: usize,
}

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn scan(&self, text: &str) -> Vec<Finding>;
}

struct Pattern {
    kind: &'static str,
    severity: Severity,
    regex: Regex,
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("valid regex")
}

/// Reihenfolge = Priorität: Bei überlappenden Funden gewinnt das Pattern,
/// das weiter oben steht. Spezifische Muster (z. B. `sk-ant-`) müssen vor
/// generischen (z. B. `sk-`) stehen.
static SECRET_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        Pattern {
            kind: "anthropic_api_key",
            severity: Severity::High,
            regex: re(r"sk-ant-[A-Za-z0-9_-]{20,}"),
        },
        Pattern {
            kind: "aws_access_key_id",
            severity: Severity::High,
            regex: re(r"AKIA[0-9A-Z]{16}"),
        },
        Pattern {
            kind: "openai_api_key",
            severity: Severity::High,
            regex: re(r"sk-[A-Za-z0-9_-]{20,}"),
        },
    ]
});

/// Reihenfolge = Priorität, siehe SECRET_PATTERNS.
static PII_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        Pattern {
            kind: "email",
            severity: Severity::Medium,
            regex: re(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        },
        Pattern {
            kind: "iban_de",
            severity: Severity::High,
            regex: re(r"\bDE\d{2}(?: ?\d{4}){4} ?\d{2}\b"),
        },
    ]
});

/// Gemeinsame Scan-Logik aller regex-basierten Detektoren:
/// alle Patterns anwenden, nach Position sortieren, Überlappungen
/// zugunsten des priorisierten Patterns auflösen.
fn scan_with(detector: &'static str, patterns: &[Pattern], text: &str) -> Vec<Finding> {
    let mut findings: Vec<Finding> = patterns
        .iter()
        .flat_map(|pattern| {
            pattern.regex.find_iter(text).map(move |m| Finding {
                detector,
                kind: pattern.kind,
                severity: pattern.severity,
                start: m.start(),
                end: m.end(),
            })
        })
        .collect();

    // sort_by_key ist stabil: bei gleichem Start bleibt die Tabellenreihenfolge.
    findings.sort_by_key(|f| f.start);

    let mut last_end = 0;
    findings.retain(|f| {
        if f.start < last_end {
            return false;
        }
        last_end = f.end;
        true
    });

    findings
}

pub struct SecretDetector;

impl Detector for SecretDetector {
    fn name(&self) -> &'static str {
        "secrets"
    }

    fn scan(&self, text: &str) -> Vec<Finding> {
        scan_with(self.name(), &SECRET_PATTERNS, text)
    }
}

pub struct PiiDetector;

impl Detector for PiiDetector {
    fn name(&self) -> &'static str {
        "pii"
    }

    fn scan(&self, text: &str) -> Vec<Finding> {
        scan_with(self.name(), &PII_PATTERNS, text)
    }
}

/// Sammlung aller aktiven Detektoren. Der Proxy kennt nur diese Struktur,
/// nicht die einzelnen Detektoren dahinter.
pub struct Detectors {
    detectors: Vec<Box<dyn Detector>>,
}

impl Detectors {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self { detectors }
    }

    /// Die Standard-Detektoren von Hedge.
    pub fn default_set() -> Self {
        Self::new(vec![Box::new(SecretDetector), Box::new(PiiDetector)])
    }

    /// Lässt alle Detektoren laufen, Ergebnis nach Position sortiert.
    /// Funde verschiedener Detektoren dürfen sich überlappen; das
    /// Zusammenführen von Bereichen ist Sache des Redactors.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings: Vec<Finding> = self
            .detectors
            .iter()
            .flat_map(|detector| detector.scan(text))
            .collect();

        findings.sort_by_key(|f| f.start);
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::{Detector, Detectors, Finding, PiiDetector, SecretDetector, Severity};

    // Generated placeholders only; these are not real API keys.
    fn fake_key(character: char, length: usize) -> String {
        format!("sk-ant-{}", character.to_string().repeat(length))
    }

    /// Pro Stelle ein Fund; bei Überlappung gewinnt das spezifischere Pattern
    /// (Reihenfolge in SECRET_PATTERNS).
    #[test]
    fn overlapping_patterns_report_the_most_specific() {
        let text = fake_key('x', 20);

        let findings = SecretDetector.scan(&text);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "anthropic_api_key");
    }

    #[test]
    fn findings_are_sorted_by_position() {
        let aws = "AKIAIOSFODNN7EXAMPLE";
        let anthropic = fake_key('x', 20);
        let text = format!("{aws} dann {anthropic}");

        let findings = SecretDetector.scan(&text);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].kind, "aws_access_key_id");
        assert_eq!(findings[1].kind, "anthropic_api_key");
    }

    #[test]
    fn one_key_has_exact_byte_offsets_and_metadata() {
        let key = fake_key('x', 20);
        let prefix = "🔒 Grüße: ";
        let text = format!("{prefix}{key} Ende");

        let findings = SecretDetector.scan(&text);

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.detector, "secrets");
        assert_eq!(finding.kind, "anthropic_api_key");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.start, prefix.len());
        assert_eq!(finding.end, prefix.len() + key.len());
        assert_eq!(&text[finding.start..finding.end], key);
    }

    #[test]
    fn normal_text_has_no_findings() {
        assert!(
            SecretDetector
                .scan("Normaler Text ohne API-Key.")
                .is_empty()
        );
    }

    #[test]
    fn two_keys_are_returned_in_text_order() {
        let first = fake_key('x', 20);
        let second = fake_key('y', 24);
        let text = format!("{first}, {second}");

        let findings = SecretDetector.scan(&text);

        assert_eq!(findings.len(), 2);
        assert_eq!(&text[findings[0].start..findings[0].end], first);
        assert_eq!(&text[findings[1].start..findings[1].end], second);
        assert!(findings[0].end <= findings[1].start);
    }

    #[test]
    fn fewer_than_twenty_characters_are_not_an_anthropic_key() {
        for text in ["sk-ant-kurz".to_owned(), fake_key('x', 19)] {
            let findings = SecretDetector.scan(&text);
            assert!(
                findings.iter().all(|f| f.kind != "anthropic_api_key"),
                "got: {findings:?}"
            );
        }
    }

    #[test]
    fn email_has_exact_byte_offsets() {
        let email = "max.mustermann+test@example.org";
        let text = format!("Kontakt: {email} bitte");

        let findings = PiiDetector.scan(&text);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "pii");
        assert_eq!(findings[0].kind, "email");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(&text[findings[0].start..findings[0].end], email);
    }

    #[test]
    fn iban_matches_with_and_without_spaces() {
        // Beispiel-IBAN der Deutschen Bundesbank, kein echtes Konto.
        for iban in ["DE89 3704 0044 0532 0130 00", "DE89370400440532013000"] {
            let text = format!("IBAN {iban} Ende");

            let findings = PiiDetector.scan(&text);

            assert_eq!(findings.len(), 1, "got: {findings:?}");
            assert_eq!(findings[0].kind, "iban_de");
            assert_eq!(&text[findings[0].start..findings[0].end], iban);
        }
    }

    #[test]
    fn email_like_strings_without_tld_do_not_match() {
        for text in ["foo@bar", "v1.2.3@2024", "user@localhost"] {
            let findings = PiiDetector.scan(text);
            assert!(findings.is_empty(), "{text}: {findings:?}");
        }
    }

    #[test]
    fn iban_inside_longer_digit_run_does_not_match() {
        let findings = PiiDetector.scan("XXDE89370400440532013000999");
        assert!(findings.is_empty(), "got: {findings:?}");
    }

    #[test]
    fn default_set_runs_all_detectors_in_text_order() {
        let email = "max@example.org";
        let key = fake_key('x', 20);
        let text = format!("{email} und {key}");

        let findings = Detectors::default_set().scan(&text);

        assert_eq!(findings.len(), 2, "got: {findings:?}");
        assert_eq!(findings[0].detector, "pii");
        assert_eq!(&text[findings[0].start..findings[0].end], email);
        assert_eq!(findings[1].detector, "secrets");
        assert_eq!(&text[findings[1].start..findings[1].end], key);
    }

    /// Beweist, dass jeder Typ, der den Detector-Vertrag erfüllt,
    /// in die Sammlung passt – auch einer, den detect.rs nicht kennt.
    struct AlwaysFinds;

    impl Detector for AlwaysFinds {
        fn name(&self) -> &'static str {
            "test"
        }

        fn scan(&self, _text: &str) -> Vec<Finding> {
            vec![Finding {
                detector: self.name(),
                kind: "always",
                severity: Severity::Low,
                start: 0,
                end: 1,
            }]
        }
    }

    #[test]
    fn any_detector_implementation_can_be_plugged_in() {
        let detectors = Detectors::new(vec![Box::new(AlwaysFinds)]);

        let findings = detectors.scan("irgendwas");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "test");
        assert_eq!(findings[0].kind, "always");
    }

    #[test]
    fn empty_set_finds_nothing() {
        let detectors = Detectors::new(vec![]);

        assert!(detectors.scan(&fake_key('x', 20)).is_empty());
    }
}
