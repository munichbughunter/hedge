"""hedge-presidio: der kleine HTTP-Dienst vor dem Presidio-Analyzer.

Spricht denselben Vertrag wie der Server des Presidio-Projekts, beschränkt
auf das, was Hedge braucht:

    GET  /health   200, sobald die Modelle geladen sind
    GET  /info     Version, Sprachen und Modelle dieses Images
    POST /analyze  {"text", "language", "entities"?, "score_threshold"?}
                   -> [{"entity_type", "start", "end", "score"}]

Bewusst nicht dabei: Erkenner, die mit der Anfrage mitkommen (beliebige
Regex von außen), Entscheidungsprotokolle, Stapelanfragen. Texte und Funde
werden nie geloggt.
"""

import logging
import os
from importlib.metadata import version

import yaml
from flask import Flask, jsonify, request
from presidio_analyzer import AnalyzerEngineProvider

CONF_FILE = os.environ.get("HEDGE_ANALYZER_CONF", "analyzer.yaml")
# Hedge schickt Stücke von höchstens 20 000 Zeichen. Das hier ist nur die
# Obergrenze gegen Anfragen, die den Dienst lahmlegen würden.
MAX_CHARS = int(os.environ.get("HEDGE_MAX_CHARS", "200000"))

log = logging.getLogger("hedge-presidio")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")

with open(CONF_FILE, encoding="utf-8") as fh:
    _conf = yaml.safe_load(fh)

LANGUAGES = list(_conf["supported_languages"])
MODELS = [m["model_name"] for m in _conf["nlp_configuration"]["models"]]

engine = AnalyzerEngineProvider(analyzer_engine_conf_file=CONF_FILE).create_engine()
ENTITIES = {lang: sorted(engine.get_supported_entities(lang)) for lang in LANGUAGES}

app = Flask(__name__)
log.info(
    "hedge-presidio ready: presidio %s, languages %s, models %s",
    version("presidio_analyzer"),
    ", ".join(LANGUAGES),
    ", ".join(MODELS),
)


class BadRequest(Exception):
    pass


def _analyze(body):
    if not isinstance(body, dict):
        raise BadRequest("the request body must be a JSON object")
    text = body.get("text")
    language = body.get("language")
    if not isinstance(text, str) or not text:
        raise BadRequest("No text provided")
    if len(text) > MAX_CHARS:
        raise BadRequest(f"text is longer than {MAX_CHARS} characters")
    if language not in LANGUAGES:
        raise BadRequest(
            f"language {language!r} is not available in this image (available: {', '.join(LANGUAGES)})"
        )
    entities = body.get("entities") or None
    if entities is not None and not (
        isinstance(entities, list) and all(isinstance(e, str) for e in entities)
    ):
        raise BadRequest("entities must be a list of names")
    threshold = body.get("score_threshold")
    if threshold is not None and not isinstance(threshold, (int, float)):
        raise BadRequest("score_threshold must be a number")
    results = engine.analyze(
        text=text,
        language=language,
        entities=entities,
        score_threshold=threshold,
    )
    return [
        {
            "entity_type": r.entity_type,
            "start": r.start,
            "end": r.end,
            "score": round(float(r.score), 4),
        }
        for r in results
    ]


@app.get("/health")
def health():
    return "hedge-presidio is up"


@app.get("/info")
def info():
    return jsonify(
        service="hedge-presidio",
        presidio=version("presidio_analyzer"),
        languages=LANGUAGES,
        models=MODELS,
        entities=ENTITIES,
    )


@app.post("/analyze")
def analyze():
    try:
        return jsonify(_analyze(request.get_json(silent=True)))
    except BadRequest as e:
        return jsonify(error=str(e)), 400
    except Exception as e:  # noqa: BLE001 - der Text darf nicht ins Log
        log.error("analysis failed: %s", type(e).__name__)
        return jsonify(error=f"analysis failed ({type(e).__name__})"), 500


@app.errorhandler(404)
def not_found(_e):
    return jsonify(error="not found"), 404


def selftest():
    """Läuft beim Bau des Images: Findet jede Sprache den Namen im Testsatz?

    Dieselben Sätze benutzt Hedge, bevor es ein Presidio für bereit erklärt.
    Ein Image, das hier scheitert, wird nicht gebaut.
    """
    sentences = {
        "de": ("Gestern hat Jörg Müller aus Hamburg bei uns angerufen.", "Jörg Müller"),
        "en": ("Yesterday John Smith from London called our office.", "John Smith"),
    }
    for lang in LANGUAGES:
        if lang not in sentences:
            engine.analyze(text="Hedge checks whether this language is available.", language=lang)
            print(f"selftest {lang}: language is available (no test sentence)")
            continue
        text, name = sentences[lang]
        start = text.index(name)
        hits = _analyze({"text": text, "language": lang, "entities": ["PERSON"], "score_threshold": 0.3})
        if not any(h["start"] < start + len(name) and start < h["end"] for h in hits):
            raise SystemExit(f"selftest {lang}: {name!r} was not found in {text!r}")
        print(f"selftest {lang}: ok")


if __name__ == "__main__":
    selftest()
