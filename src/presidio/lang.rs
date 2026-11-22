//! In welcher Sprache ein Text analysiert wird, und die Testsätze, mit denen
//! Hedge prüft, ob ein Presidio diese Sprache wirklich kann.
//!
//! Presidio analysiert immer genau eine Sprache pro Aufruf. Das falsche
//! Modell liefert nicht nur weniger, sondern Unsinn: Ein englisches Modell
//! hält in deutschem Text großgeschriebene Wörter für Namen. Deshalb wählt
//! Hedge die Sprache pro Text und analysiert genau einmal.

use whatlang::{Detector, Lang};

/// So viele Zeichen vom Anfang eines Textes reichen für die Erkennung.
const SAMPLE_CHARS: usize = 1500;

/// ISO 639-1 (wie Presidio sie erwartet) → whatlang.
fn lang_of(code: &str) -> Option<Lang> {
    let iso3 = match code.split('-').next().unwrap_or(code) {
        "de" => "deu",
        "en" => "eng",
        "fr" => "fra",
        "es" => "spa",
        "it" => "ita",
        "nl" => "nld",
        "pt" => "por",
        "pl" => "pol",
        "sv" => "swe",
        "da" => "dan",
        "fi" => "fin",
        "nb" | "no" => "nob",
        "cs" => "ces",
        "sk" => "slk",
        "hu" => "hun",
        "ro" => "ron",
        "tr" => "tur",
        "el" => "ell",
        "ru" => "rus",
        "uk" => "ukr",
        "bg" => "bul",
        "hr" => "hrv",
        "he" => "heb",
        "ar" => "ara",
        "hi" => "hin",
        "ja" => "jpn",
        "ko" => "kor",
        "zh" => "cmn",
        _ => return None,
    };
    Lang::from_code(iso3)
}

/// Wählt für jeden Text eine der konfigurierten Sprachen.
pub struct Picker {
    languages: Vec<String>,
    /// `None`, wenn es nichts zu entscheiden gibt (eine Sprache).
    detector: Option<Detector>,
    known: Vec<(Lang, usize)>,
}

impl Picker {
    pub fn new(languages: &[String]) -> Self {
        let known: Vec<(Lang, usize)> = languages
            .iter()
            .enumerate()
            .filter_map(|(i, code)| lang_of(code).map(|l| (l, i)))
            .collect();
        let detector = (languages.len() > 1 && known.len() > 1)
            .then(|| Detector::with_allowlist(known.iter().map(|(l, _)| *l).collect()));
        Self {
            languages: languages.to_vec(),
            detector,
            known,
        }
    }

    /// Die Sprache für diesen Text. Lässt sie sich nicht sicher erkennen
    /// (kurzer Text, Code, Zahlenkolonnen), gilt die erste der Liste.
    pub fn pick(&self, text: &str) -> &str {
        let fallback = self.languages.first().map(String::as_str).unwrap_or("en");
        let Some(detector) = &self.detector else {
            return fallback;
        };
        let end = text
            .char_indices()
            .nth(SAMPLE_CHARS)
            .map_or(text.len(), |(i, _)| i);
        match detector.detect(&text[..end]) {
            Some(info) if info.is_reliable() => self
                .known
                .iter()
                .find(|(l, _)| *l == info.lang())
                .map(|(_, i)| self.languages[*i].as_str())
                .unwrap_or(fallback),
            _ => fallback,
        }
    }
}

/// Ein Satz mit einem Namen darin. Findet ein Presidio den Namen nicht, hat
/// es für diese Sprache kein brauchbares Modell.
pub struct Canary {
    pub text: &'static str,
    pub name: &'static str,
}

/// Testsatz für eine Sprache. Nur für Sprachen, deren Satz gegen ein echtes
/// Presidio geprüft ist; für alle anderen prüft Hedge nur, ob Presidio die
/// Sprache annimmt.
pub fn canary(language: &str) -> Option<Canary> {
    match language {
        "de" => Some(Canary {
            text: "Gestern hat Jörg Müller aus Hamburg bei uns angerufen.",
            name: "Jörg Müller",
        }),
        "en" => Some(Canary {
            text: "Yesterday John Smith from London called our office.",
            name: "John Smith",
        }),
        _ => None,
    }
}

/// Ein harmloser Satz ohne Personenbezug, um zu sehen, ob Presidio eine
/// Sprache überhaupt annimmt.
pub const NEUTRAL: &str = "Hedge checks whether this language is available.";

#[cfg(test)]
mod tests {
    use super::*;

    fn langs(codes: &[&str]) -> Vec<String> {
        codes.iter().map(|c| c.to_string()).collect()
    }

    #[test]
    fn one_language_is_always_that_language() {
        let p = Picker::new(&langs(&["en"]));
        assert_eq!(p.pick("Guten Morgen, wie geht es Ihnen heute?"), "en");
    }

    #[test]
    fn german_and_english_are_told_apart() {
        let p = Picker::new(&langs(&["de", "en"]));
        assert_eq!(
            p.pick("Kannst du bitte die Rechnung für Frau Schmidt noch einmal prüfen und mir das Ergebnis schicken?"),
            "de"
        );
        assert_eq!(
            p.pick("Could you please check the invoice for Mrs Smith again and send me the result afterwards?"),
            "en"
        );
    }

    #[test]
    fn unclear_text_falls_back_to_the_first_language() {
        let de_first = Picker::new(&langs(&["de", "en"]));
        let en_first = Picker::new(&langs(&["en", "de"]));
        for text in ["42", "ok", "{}[]();", ""] {
            assert_eq!(de_first.pick(text), "de", "{text:?}");
            assert_eq!(en_first.pick(text), "en", "{text:?}");
        }
    }

    #[test]
    fn unknown_codes_are_never_chosen_by_detection_but_can_be_the_fallback() {
        let p = Picker::new(&langs(&["xx", "en", "de"]));
        assert_eq!(p.pick("??"), "xx");
        assert_eq!(
            p.pick(
                "The quick brown fox jumps over the lazy dog and keeps running through the forest."
            ),
            "en"
        );
    }

    #[test]
    fn canaries_contain_their_name() {
        for l in ["de", "en"] {
            let c = canary(l).unwrap();
            assert!(c.text.contains(c.name));
        }
        assert!(canary("fr").is_none());
    }
}
