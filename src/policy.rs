use crate::config::Mode;
use crate::detect::{Finding, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Redact,
    Block { reason: String },
}

pub fn decide(findings: &[Finding], mode: Mode) -> Decision {
    let max_severity = findings.iter().map(|f| f.severity).max();

    match (mode, max_severity) {
        (Mode::Observe, _) => Decision::Allow,
        (_, None) => Decision::Allow,
        (Mode::Redact, Some(_)) => Decision::Redact,
        (Mode::Block, Some(Severity::Low | Severity::Medium)) => Decision::Redact,
        (Mode::Block, Some(Severity::High)) => Decision::Block {
            reason: block_reason(findings),
        },
    }
}

fn block_reason(findings: &[Finding]) -> String {
    let kinds: Vec<&str> = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .map(|f| f.kind)
        .collect();

    format!(
        "{} high-severity finding(s): {}",
        kinds.len(),
        kinds.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity) -> Finding {
        Finding {
            detector: "test",
            kind: "test",
            severity,
            start: 0,
            end: 1,
        }
    }

    fn with_kind(kind: &'static str, severity: Severity) -> Finding {
        Finding {
            kind,
            ..finding(severity)
        }
    }

    #[test]
    fn observe_always_allows() {
        assert_eq!(decide(&[], Mode::Observe), Decision::Allow);
        assert_eq!(
            decide(&[finding(Severity::Low)], Mode::Observe),
            Decision::Allow
        );
        assert_eq!(
            decide(&[finding(Severity::Medium)], Mode::Observe),
            Decision::Allow
        );
        assert_eq!(
            decide(&[finding(Severity::High)], Mode::Observe),
            Decision::Allow
        );
    }

    #[test]
    fn redact_mode_allows_clean_and_redacts_any_finding() {
        assert_eq!(decide(&[], Mode::Redact), Decision::Allow);
        assert_eq!(
            decide(&[finding(Severity::Low)], Mode::Redact),
            Decision::Redact
        );
        assert_eq!(
            decide(&[finding(Severity::Medium)], Mode::Redact),
            Decision::Redact
        );
        assert_eq!(
            decide(&[finding(Severity::High)], Mode::Redact),
            Decision::Redact
        );
    }

    #[test]
    fn block_mode_blocks_only_high_severity() {
        assert_eq!(decide(&[], Mode::Block), Decision::Allow);
        assert_eq!(
            decide(&[finding(Severity::Low)], Mode::Block),
            Decision::Redact
        );
        assert_eq!(
            decide(&[finding(Severity::Medium)], Mode::Block),
            Decision::Redact
        );
        assert!(matches!(
            decide(&[finding(Severity::High)], Mode::Block),
            Decision::Block { .. }
        ));
    }

    #[test]
    fn highest_severity_wins_in_mixed_findings() {
        let findings = [
            finding(Severity::Low),
            finding(Severity::High),
            finding(Severity::Medium),
        ];

        assert!(matches!(
            decide(&findings, Mode::Block),
            Decision::Block { .. }
        ));
        assert_eq!(decide(&findings, Mode::Redact), Decision::Redact);
    }

    #[test]
    fn block_reason_names_count_and_kinds_of_high_findings_only() {
        let findings = [
            with_kind("anthropic_api_key", Severity::High),
            with_kind("email", Severity::Medium),
            with_kind("iban_de", Severity::High),
        ];

        let reason = block_reason(&findings);

        assert_eq!(
            reason,
            "2 high-severity finding(s): anthropic_api_key, iban_de"
        );
    }

    #[test]
    fn block_decision_carries_the_reason() {
        let decision = decide(
            &[with_kind("aws_access_key_id", Severity::High)],
            Mode::Block,
        );

        match decision {
            Decision::Block { reason } => {
                assert!(reason.contains("aws_access_key_id"), "got: {reason}")
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }
}
