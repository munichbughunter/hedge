# hedge-presidio: Presidio-Analyzer mit Deutsch und Englisch, so wie Hedge
# ihn erwartet. Gebaut wird aus diesem Verzeichnis:
#
#   docker build -t ghcr.io/munichbughunter/hedge-presidio:<version> deploy/presidio
#
# oder ohne Repo, aus dem Binary:  hedge presidio enable --build
#
# Das Basis-Image gibt es für amd64 und arm64; auf Apple Silicon läuft der
# Container damit ohne Emulation.
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=3000 \
    WORKERS=1

WORKDIR /app

# Sicherheitsupdates des Betriebssystems.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install -r requirements.txt

# Die Sprachmodelle stehen in analyzer.yaml; spaCy holt zu jedem die Fassung,
# die zur installierten spaCy-Version gehört.
COPY analyzer.yaml ./
RUN python -c "import yaml, spacy.cli; [spacy.cli.download(m['model_name']) for m in yaml.safe_load(open('analyzer.yaml'))['nlp_configuration']['models']]"

COPY server.py ./

# Kein Image ohne bestandenen Test: Jede Sprache muss den Namen in ihrem
# Testsatz finden.
RUN python server.py

RUN useradd --system --uid 10001 --home-dir /app hedge
USER 10001

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD python -c "import os, urllib.request as u; u.build_opener(u.ProxyHandler({})).open('http://127.0.0.1:' + os.environ.get('PORT', '3000') + '/health', timeout=2)"

LABEL org.opencontainers.image.title="hedge-presidio" \
      org.opencontainers.image.description="Presidio analyzer (de, en) for the Hedge AI guard proxy" \
      org.opencontainers.image.source="https://github.com/munichbughunter/hedge" \
      org.opencontainers.image.licenses="MIT" \
      dev.hedge.presidio.languages="de,en"

# --preload lädt die Modelle einmal und teilt sie zwischen den Workern.
CMD ["sh", "-c", "exec gunicorn --preload --workers \"$WORKERS\" --bind \"0.0.0.0:$PORT\" --timeout 120 --graceful-timeout 10 server:app"]
