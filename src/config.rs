use serde::Deserialize;
use std::fs::read_to_string;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub server: Server,
    pub upstreams: Vec<Upstream>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub listen: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Observe,
    Redact,
    Block,
}

impl Config {
    /// Parst Config aus einem TOML-Text
    pub fn from_toml(text: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(text)
    }

    /// Liest die Datei und parst sie
    pub fn load(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
        let config_str = read_to_string(path)?;
        Ok(Config::from_toml(&config_str)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        mode = "observe"

        [server]
        listen = "127.0.0.1:18765"

        [[upstreams]]
        name = "anthropic"
        url = "https://api.anthropic.com"
    "#;

    #[test]
    fn parses_valid_config() {
        let cfg = Config::from_toml(VALID).expect("valid config must parse");

        assert_eq!(cfg.mode, Mode::Observe);
        assert_eq!(cfg.server.listen, "127.0.0.1:18765");
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.upstreams[0].name, "anthropic");
        assert_eq!(cfg.upstreams[0].url, "https://api.anthropic.com");
    }

    #[test]
    fn rejects_unknown_mode() {
        let invalid = VALID.replace("observe", "yolo");

        let result = Config::from_toml(&invalid);

        assert!(result.is_err(), "mode = \"yolo\" must be rejected");
    }

    #[test]
    fn rejects_missing_server() {
        let without_server = r#"
            mode = "observe"

            [[upstream]]
            name = "anthropic"
            url = "https://api.anthropic.com"
        "#;

        let result = Config::from_toml(without_server);

        assert!(result.is_err(), "config without [server] must be rejected");
    }

    #[test]
    fn error_message_names_the_problem() {
        let invalid = VALID.replace("observe", "yolo");

        let err = Config::from_toml(&invalid).unwrap_err();

        assert!(err.to_string().contains("yolo"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_field() {
        let typo = VALID.replace("url =", "urll =");

        let result = Config::from_toml(&typo);

        assert!(result.is_err(), "unknown field `urll` must be rejected");
    }
}
